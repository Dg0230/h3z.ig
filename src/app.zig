const std = @import("std");
const Context = @import("context.zig").Context;
const Router = @import("router.zig").Router;
const Handler = @import("router.zig").Handler;
const RouteGroup = @import("router.zig").RouteGroup;
const Middleware = @import("middleware.zig").Middleware;
const Request = @import("http/request.zig");
const HttpMethod = @import("http/request.zig").HttpMethod;
const Response = @import("http/response.zig").Response;
const parseRequest = @import("http/request.zig").parseRequest;
const RateLimiter = @import("middleware.zig").rateLimit.RateLimiter;
const BufferPool = @import("memory/buffer_pool.zig").BufferPool;
const BufferSize = @import("memory/buffer_pool.zig").BufferSize;
const cors = @import("middleware.zig").cors;
const rateLimit = @import("middleware.zig").rateLimit;

/// Application configuration
pub const AppConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 3000,
    max_connections: u32 = 1000,
    buffer_size: usize = 8192,
    read_timeout_ms: u32 = 30000,
    write_timeout_ms: u32 = 30000,
    keep_alive: bool = true,

    // TLS configuration
    enable_tls: bool = false,
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,

    // Performance settings
    reuse_address: bool = true,
    reuse_port: bool = false,
    tcp_nodelay: bool = true,
    tcp_keepalive: bool = true,

    // Logging
    log_requests: bool = true,
    log_level: std.log.Level = .info,
};

/// Connection pool for managing client connections
const ConnectionPool = struct {
    connections: std.ArrayList(std.net.Server.Connection),
    available: std.atomic.Value(u32),
    max_connections: u32,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, max_connections: u32) ConnectionPool {
        return ConnectionPool{
            .connections = std.ArrayList(std.net.Server.Connection).init(allocator),
            .available = std.atomic.Value(u32).init(0),
            .max_connections = max_connections,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |conn| {
            conn.stream.close();
        }
        self.connections.deinit();
    }

    pub fn acquire(self: *ConnectionPool) ?std.net.Server.Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.connections.items.len > 0) {
            const conn = self.connections.pop();
            _ = self.available.fetchSub(1, .monotonic);
            return conn;
        }

        return null;
    }

    pub fn release(self: *ConnectionPool, conn: std.net.Server.Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.connections.items.len < self.max_connections) {
            self.connections.append(conn) catch {
                conn.stream.close();
                return;
            };
            _ = self.available.fetchAdd(1, .monotonic);
        } else {
            conn.stream.close();
        }
    }
};

/// HTTP server statistics
pub const ServerStats = struct {
    requests_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    requests_active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    connections_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    connections_active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    bytes_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    errors_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn requestStarted(self: *ServerStats) void {
        _ = self.requests_total.fetchAdd(1, .monotonic);
        _ = self.requests_active.fetchAdd(1, .monotonic);
    }

    pub fn requestFinished(self: *ServerStats) void {
        _ = self.requests_active.fetchSub(1, .monotonic);
    }

    pub fn connectionStarted(self: *ServerStats) void {
        _ = self.connections_total.fetchAdd(1, .monotonic);
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    pub fn connectionFinished(self: *ServerStats) void {
        _ = self.connections_active.fetchSub(1, .monotonic);
    }

    pub fn errorOccurred(self: *ServerStats) void {
        _ = self.errors_total.fetchAdd(1, .monotonic);
    }

    pub fn bytesTransferred(self: *ServerStats, sent: u64, received: u64) void {
        _ = self.bytes_sent.fetchAdd(sent, .monotonic);
        _ = self.bytes_received.fetchAdd(received, .monotonic);
    }
};

/// Main H3Z application
pub const App = struct {
    router: Router,
    config: AppConfig,
    stats: ServerStats,
    allocator: std.mem.Allocator,
    _server: ?std.net.Server = null,
    _connection_pool: ?ConnectionPool = null,
    _shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    _rate_limiter: ?RateLimiter = null,
    _buffer_pool: ?BufferPool = null,

    /// Initialize a new application
    pub fn init(allocator: std.mem.Allocator, config: AppConfig) App {
        return App{
            .router = Router.init(allocator),
            .config = config,
            .stats = ServerStats{},
            .allocator = allocator,
        };
    }

    /// Clean up application resources
    pub fn deinit(self: *App) void {
        if (self._server) |*server| {
            server.deinit();
        }

        if (self._connection_pool) |*pool| {
            pool.deinit();
        }

        if (self._rate_limiter) |*limiter| {
            limiter.deinit();
        }

        // Clean up buffer pool
        if (self._buffer_pool) |*pool| {
            pool.deinit();
        }

        // Clean up global rate limiter if any middleware was using it
        rateLimit.deinitGlobal();

        self.router.deinit();
    }

    /// Add global middleware
    pub fn use(self: *App, middleware: Middleware) !void {
        try self.router.use(middleware);
    }

    /// Add GET route
    pub fn get(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.get(pattern, handler);
    }

    /// Add POST route
    pub fn post(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.post(pattern, handler);
    }

    /// Add PUT route
    pub fn put(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.put(pattern, handler);
    }

    /// Add DELETE route
    pub fn delete(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.delete(pattern, handler);
    }

    /// Add PATCH route
    pub fn patch(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.patch(pattern, handler);
    }

    /// Add HEAD route
    pub fn head(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.head(pattern, handler);
    }

    /// Add OPTIONS route
    pub fn options(self: *App, pattern: []const u8, handler: Handler) !void {
        try self.router.options(pattern, handler);
    }

    /// Create a route group
    pub fn group(self: *App, prefix: []const u8) !*RouteGroup {
        return self.router.group(prefix);
    }

    /// Start the HTTP server
    pub fn listen(self: *App) !void {
        const address = try std.net.Address.parseIp(self.config.host, self.config.port);

        self._server = try address.listen(.{
            .reuse_address = self.config.reuse_address,
            .reuse_port = self.config.reuse_port,
        });

        // Initialize connection pool
        self._connection_pool = ConnectionPool.init(self.allocator, self.config.max_connections);

        // Initialize buffer pool
        self._buffer_pool = BufferPool.init(self.allocator, .{
            .max_buffers_per_size = 16,
        });

        std.log.info("H3Z server listening on {s}:{d} (synchronous mode)", .{ self.config.host, self.config.port });

        std.log.info("Configuration: max_connections={d}, buffer_size={d}", .{ self.config.max_connections, self.config.buffer_size });

        // Main server loop
        while (!self._shutdown.load(.monotonic)) {
            self.acceptConnection() catch |err| {
                self.stats.errorOccurred();
                std.log.err("Error accepting connection: {}", .{err});

                // Small delay to prevent tight error loops
                std.time.sleep(std.time.ns_per_ms * 10);
            };
        }
    }

    /// Accept and handle a new connection
    fn acceptConnection(self: *App) !void {
        if (self._server == null) return error.ServerNotInitialized;

        std.log.info("Waiting for connection...", .{});
        const connection = try self._server.?.accept();
        self.stats.connectionStarted();

        std.log.info("Connection accepted from {}", .{connection.address});

        // In a real implementation, this should be handled in a thread pool
        // For now, we'll handle connections synchronously
        self.handleConnection(connection) catch |err| {
            self.stats.errorOccurred();
            std.log.err("Error handling connection: {}", .{err});
        };
        self.stats.connectionFinished();
    }

    /// Handle a client connection
    fn handleConnection(self: *App, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        // Set socket options
        if (self.config.tcp_nodelay) {
            // TODO: Set TCP_NODELAY
        }

        if (self.config.tcp_keepalive) {
            // TODO: Set SO_KEEPALIVE
        }

        // Connection may handle multiple requests (HTTP/1.1 keep-alive)
        while (!self._shutdown.load(.monotonic)) {
            const keep_alive = try self.handleRequest(connection);
            if (!keep_alive or !self.config.keep_alive) {
                break;
            }
        }
    }

    /// Handle a single HTTP request
    fn handleRequest(self: *App, connection: std.net.Server.Connection) !bool {
        self.stats.requestStarted();
        defer self.stats.requestFinished();

        // Get buffer from pool if available, otherwise allocate
        var managed_buffer = if (self._buffer_pool) |*pool|
            pool.acquire(BufferSize.fromSize(self.config.buffer_size)) catch null
        else
            null;

        const buffer = if (managed_buffer) |*mb|
            mb.data
        else
            try self.allocator.alloc(u8, self.config.buffer_size);

        defer {
            if (managed_buffer) |*mb| {
                if (self._buffer_pool) |*pool| {
                    pool.release(mb);
                }
            } else {
                self.allocator.free(buffer);
            }
        }

        // Simple blocking read - this should work for most cases
        const bytes_read = connection.stream.read(buffer) catch |err| {
            std.log.err("Failed to read from connection: {}", .{err});
            return false;
        };

        self.stats.bytesTransferred(0, bytes_read);

        if (bytes_read == 0) {
            return false; // Connection closed
        }

        std.log.info("Received {} bytes: {s}", .{ bytes_read, buffer[0..@min(100, bytes_read)] });

        // Parse HTTP request
        var request = parseRequest(self.allocator, buffer[0..bytes_read]) catch |err| {
            // Log the raw request data for debugging
            const request_data = if (bytes_read > 200) buffer[0..200] else buffer[0..bytes_read];
            std.log.err("Failed to parse request: {} - Raw data: {s}", .{ err, request_data });

            // Send 400 Bad Request
            const bad_request_response = "HTTP/1.1 400 Bad Request\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "Content-Length: 11\r\n" ++
                "Connection: close\r\n" ++
                "\r\n" ++
                "Bad Request";

            _ = try connection.stream.writeAll(bad_request_response);
            self.stats.bytesTransferred(bad_request_response.len, 0);

            return false;
        };
        defer request.deinit();

        // Create context
        var ctx = Context.init(self.allocator, request);
        defer ctx.deinit();

        // Handle request through router
        self.router.handle(&ctx) catch |err| {
            self.stats.errorOccurred();

            // Send 500 Internal Server Error
            ctx.response.status = .internal_server_error;
            ctx.response.body = null;
            _ = ctx.text("Internal Server Error") catch {};

            std.log.err("Handler error: {}", .{err});
        };

        // Send response
        const response_bytes = try self.sendResponse(connection.stream, &ctx.response);
        self.stats.bytesTransferred(response_bytes, 0);

        // Check for keep-alive
        const connection_header = request.header("connection");
        const keep_alive = if (connection_header) |conn|
            std.ascii.eqlIgnoreCase(conn, "keep-alive")
        else
            request.version == .@"1.1"; // HTTP/1.1 defaults to keep-alive

        return keep_alive;
    }

    /// Send HTTP response to client
    fn sendResponse(self: *App, stream: std.net.Stream, response: *const Response) !usize {
        _ = self;

        var bytes_written: usize = 0;
        var writer = stream.writer();

        // Status line
        const status_line = try std.fmt.allocPrint(response.allocator, "HTTP/1.1 {d} {s}\r\n", .{
            @intFromEnum(response.status),
            response.status.phrase(),
        });
        defer response.allocator.free(status_line);

        try writer.writeAll(status_line);
        bytes_written += status_line.len;

        // Headers
        var header_iter = response.headers.iterator();
        while (header_iter.next()) |entry| {
            const header_line = try std.fmt.allocPrint(response.allocator, "{s}: {s}\r\n", .{ entry.key, entry.value });
            defer response.allocator.free(header_line);

            try writer.writeAll(header_line);
            bytes_written += header_line.len;
        }

        // End of headers
        try writer.writeAll("\r\n");
        bytes_written += 2;

        // Body
        if (response.body) |body| {
            try writer.writeAll(body);
            bytes_written += body.len;
        }

        return bytes_written;
    }

    /// Graceful shutdown
    pub fn shutdown(self: *App) void {
        std.log.info("Shutting down H3Z server...");
        self._shutdown.store(true, .monotonic);

        if (self._server) |*server| {
            server.deinit();
            self._server = null;
        }

        std.log.info("Server shutdown complete");
    }

    /// Get server statistics
    pub fn getStats(self: *const App) ServerStats {
        return self.stats;
    }

    /// Print server statistics
    pub fn printStats(self: *const App) void {
        const stats = self.getStats();

        std.log.info("Server Statistics:", .{});
        std.log.info("  Requests: {} total, {} active", .{
            stats.requests_total.load(.monotonic),
            stats.requests_active.load(.monotonic),
        });
        std.log.info("  Connections: {} total, {} active", .{
            stats.connections_total.load(.monotonic),
            stats.connections_active.load(.monotonic),
        });
        std.log.info("  Bytes: {} sent, {} received", .{
            stats.bytes_sent.load(.monotonic),
            stats.bytes_received.load(.monotonic),
        });
        std.log.info("  Errors: {}", .{stats.errors_total.load(.monotonic)});
    }

    /// Handle requests in a test environment
    pub fn testRequest(self: *App, method: HttpMethod, path: []const u8, body: ?[]const u8) !Response {
        var request = Request.Request.init(self.allocator);
        request.method = method;
        // Create a minimal URI for testing - just store the path
        request.uri = std.Uri{
            .scheme = "http",
            .user = null,
            .password = null,
            .host = .{ .raw = "localhost" },
            .port = null,
            .path = .{ .raw = path },
            .query = null,
            .fragment = null,
        };
        request.body = if (body) |b| try self.allocator.dupe(u8, b) else null;
        defer request.deinit();

        var ctx = Context.init(self.allocator, request);
        defer ctx.deinit();

        try self.router.handle(&ctx);

        // Return a copy of the response
        var response = Response.init(self.allocator);
        response.status = ctx.response.status;

        // Copy headers
        var header_iter = ctx.response.headers.iterator();
        while (header_iter.next()) |entry| {
            _ = try response.setHeader(entry.key, entry.value);
        }

        // Copy body
        if (ctx.response.body) |body_data| {
            response.body = try self.allocator.dupe(u8, body_data);
            response._body_owned = true;
        }

        return response;
    }

    /// Get or initialize rate limiter
    pub fn getRateLimiter(self: *App) !*RateLimiter {
        if (self._rate_limiter == null) {
            self._rate_limiter = RateLimiter.init(self.allocator);
        }
        return &self._rate_limiter.?;
    }
};

test "app basic functionality" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = App.init(allocator, .{});
    defer app.deinit();

    const TestHandler = struct {
        fn handle(ctx: *Context) !void {
            try ctx.json(.{ .message = "Hello, H3Z!" });
        }
    };

    try app.get("/", TestHandler.handle);

    var response = try app.testRequest(.GET, "/", null);
    defer response.deinit();

    try testing.expect(response.status == .ok);
    try testing.expect(response.body != null);
    try testing.expect(std.mem.indexOf(u8, response.body.?, "Hello, H3Z!") != null);
}

test "app middleware" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = App.init(allocator, .{});
    defer app.deinit();

    // Add CORS middleware
    try app.use(cors.default());

    const TestHandler = struct {
        fn handle(ctx: *Context) !void {
            try ctx.text("OK");
        }
    };

    try app.get("/test", TestHandler.handle);

    var response = try app.testRequest(.GET, "/test", null);
    defer response.deinit();

    try testing.expect(response.getHeader("Access-Control-Allow-Origin") != null);
    try testing.expectEqualStrings("*", response.getHeader("Access-Control-Allow-Origin").?);
}
