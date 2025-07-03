const std = @import("std");
const Context = @import("context.zig").Context;
const Request = @import("http/request.zig").Request;

/// Middleware execution result
pub const MiddlewareResult = enum {
    /// Continue to next middleware
    continue_chain,
    /// Stop processing and return response
    halt,
    /// Abort with error
    abort,
};

/// Middleware function type - returns result indicating what to do next
pub const MiddlewareFn = *const fn (ctx: *Context) anyerror!MiddlewareResult;

/// Route handler function type
pub const HandlerFn = *const fn (ctx: *Context) anyerror!void;

/// Middleware wrapper
pub const Middleware = struct {
    handler: MiddlewareFn,

    pub fn call(self: Middleware, ctx: *Context) anyerror!MiddlewareResult {
        return self.handler(ctx);
    }
};

/// Compile-time middleware stack builder that generates optimized handler
pub fn MiddlewareStack(comptime middlewares: []const Middleware) type {
    return struct {
        const Self = @This();

        /// Handle request through middleware stack
        pub fn handle(ctx: *Context, final_handler: HandlerFn) anyerror!void {
            // Use comptime to unroll the middleware chain at compile time
            inline for (middlewares) |middleware| {
                const result = try middleware.call(ctx);
                switch (result) {
                    .continue_chain => {
                        // Continue to next middleware
                    },
                    .halt => {
                        // Stop processing, response should be set
                        return;
                    },
                    .abort => {
                        // Abort processing
                        return;
                    },
                }
            }

            // If we reach here, execute the final handler
            try final_handler(ctx);
        }
    };
}

/// CORS middleware
pub const cors = struct {
    pub const Options = struct {
        origin: []const u8 = "*",
        methods: []const u8 = "GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS",
        headers: []const u8 = "Content-Type,Authorization,X-Requested-With",
        credentials: bool = false,
        max_age: ?u32 = null,
    };

    pub fn middleware(comptime options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    // Set CORS headers
                    try ctx.setHeader("Access-Control-Allow-Origin", options.origin);
                    try ctx.setHeader("Access-Control-Allow-Methods", options.methods);
                    try ctx.setHeader("Access-Control-Allow-Headers", options.headers);

                    if (options.credentials) {
                        try ctx.setHeader("Access-Control-Allow-Credentials", "true");
                    }

                    if (options.max_age) |max_age| {
                        const max_age_str = try std.fmt.allocPrint(ctx.allocator, "{d}", .{max_age});
                        defer ctx.allocator.free(max_age_str);
                        try ctx.setHeader("Access-Control-Max-Age", max_age_str);
                    }

                    // Handle preflight requests
                    if (ctx.isMethod(.OPTIONS)) {
                        ctx.status(.no_content);
                        return .halt; // Stop processing for OPTIONS requests
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }

    pub fn default() Middleware {
        return middleware(.{});
    }
};

/// Logger middleware
pub const logger = struct {
    pub const Format = enum {
        combined,
        common,
        dev,
        short,
        tiny,
    };

    pub fn middleware(comptime format: Format) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    const method = ctx.method().toString();
                    const path = ctx.path();
                    const ip = ctx.ip() orelse "unknown";

                    // For now, just log the incoming request
                    switch (format) {
                        .dev => {
                            std.log.info("\x1b[32m{s}\x1b[0m {s} - {s}", .{ method, path, ip });
                        },
                        .short => {
                            std.log.info("{s} {s} - {s}", .{ method, path, ip });
                        },
                        .tiny => {
                            std.log.info("{s} {s}", .{ method, path });
                        },
                        .common => {
                            std.log.info("{s} - - [{d}] \"{s} {s}\"", .{ ip, std.time.timestamp(), method, path });
                        },
                        .combined => {
                            const user_agent = ctx.userAgent() orelse "-";
                            std.log.info("{s} - - [{d}] \"{s} {s}\" - \"{s}\"", .{ ip, std.time.timestamp(), method, path, user_agent });
                        },
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }

    pub fn default() Middleware {
        return middleware(.dev);
    }
};

/// Body parser middleware
pub const bodyParser = struct {
    pub const Options = struct {
        limit: usize = 1024 * 1024, // 1MB default
        strict: bool = true,
    };

    pub fn json(comptime options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    if (ctx.request.body) |body| {
                        if (body.len > options.limit) {
                            ctx.status(.payload_too_large);
                            try ctx.text("Request body too large");
                            return .halt;
                        }

                        if (options.strict and !ctx.hasJsonBody()) {
                            ctx.status(.bad_request);
                            try ctx.text("Expected JSON content type");
                            return .halt;
                        }

                        // Validate JSON syntax by trying to parse it
                        var parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, body, .{}) catch {
                            ctx.status(.bad_request);
                            try ctx.text("Invalid JSON");
                            return .halt;
                        };
                        defer parsed.deinit();

                        // Store JSON string in locals - handlers can parse it again as needed
                        try ctx.setLocal("json_body", body);
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }

    pub fn urlencoded(comptime options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    if (ctx.request.body) |body| {
                        if (body.len > options.limit) {
                            ctx.status(.payload_too_large);
                            try ctx.text("Request body too large");
                            return .halt;
                        }

                        if (options.strict and !ctx.request.isForm()) {
                            ctx.status(.bad_request);
                            try ctx.text("Expected form content type");
                            return .halt;
                        }
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }
};

/// Rate limiting middleware
pub const rateLimit = struct {
    pub const Options = struct {
        window_ms: u64 = 15 * 60 * 1000, // 15 minutes
        max_requests: u32 = 100,
        message: []const u8 = "Too many requests",
        skip_successful: bool = false,
    };

    pub const RateLimiter = struct {
        requests: std.StringHashMap(RequestInfo),
        allocator: std.mem.Allocator,
        mutex: std.Thread.Mutex = .{},

        const RequestInfo = struct {
            count: u32,
            reset_time: i64,
        };

        pub fn init(allocator: std.mem.Allocator) RateLimiter {
            return RateLimiter{
                .requests = std.StringHashMap(RequestInfo).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *RateLimiter) void {
            // Free all IP string keys
            var it = self.requests.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            self.requests.deinit();
        }

        pub fn checkLimit(self: *RateLimiter, ip: []const u8, options: Options) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            const now = std.time.milliTimestamp();
            const reset_time = now + @as(i64, @intCast(options.window_ms));

            if (self.requests.getPtr(ip)) |info| {
                if (now > info.reset_time) {
                    // Reset window
                    info.count = 1;
                    info.reset_time = reset_time;
                    return true;
                } else {
                    info.count += 1;
                    return info.count <= options.max_requests;
                }
            } else {
                // First request from this IP - need to duplicate the IP string
                const ip_copy = self.allocator.dupe(u8, ip) catch return true; // Allow on allocation error
                self.requests.put(ip_copy, RequestInfo{
                    .count = 1,
                    .reset_time = reset_time,
                }) catch {
                    self.allocator.free(ip_copy);
                    return true;
                };
                return true;
            }
        }
    };

    // Thread-safe singleton pattern for rate limiter
    var global_limiter: ?RateLimiter = null;
    var limiter_mutex: std.Thread.Mutex = .{};
    var is_initialized: bool = false;

    /// Initialize global rate limiter with specific allocator
    pub fn initGlobal(allocator: std.mem.Allocator) void {
        limiter_mutex.lock();
        defer limiter_mutex.unlock();
        if (!is_initialized) {
            global_limiter = RateLimiter.init(allocator);
            is_initialized = true;
        }
    }

    /// Clean up global rate limiter (call this on shutdown)
    pub fn deinitGlobal() void {
        limiter_mutex.lock();
        defer limiter_mutex.unlock();
        if (global_limiter) |*limiter| {
            limiter.deinit();
            global_limiter = null;
            is_initialized = false;
        }
    }

    pub fn middleware(comptime options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    const ip = ctx.ip() orelse "unknown";

                    // Ensure global limiter is initialized
                    limiter_mutex.lock();
                    if (!is_initialized) {
                        global_limiter = RateLimiter.init(ctx.allocator);
                        is_initialized = true;
                    }
                    limiter_mutex.unlock();

                    if (!global_limiter.?.checkLimit(ip, options)) {
                        ctx.status(.too_many_requests);
                        try ctx.setHeader("Retry-After", "900"); // 15 minutes
                        try ctx.text(options.message);
                        return .halt;
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }
};

/// Static file serving middleware
pub const static = struct {
    pub const Options = struct {
        root: []const u8 = "./public",
        index: []const u8 = "index.html",
        dotfiles: bool = false, // Allow serving dotfiles
        fallthrough: bool = true, // Continue to next middleware if file not found
        max_age: ?u32 = null, // Cache control max-age in seconds
    };

    pub fn middleware(comptime options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    if (!ctx.isGet() and !ctx.isMethod(.HEAD)) {
                        return .continue_chain;
                    }

                    var path = ctx.path();

                    // Remove leading slash
                    if (path.len > 0 and path[0] == '/') {
                        path = path[1..];
                    }

                    // Check for dotfiles
                    if (!options.dotfiles and std.mem.indexOf(u8, path, "/.") != null) {
                        if (options.fallthrough) {
                            return .continue_chain;
                        } else {
                            ctx.status(.forbidden);
                            try ctx.text("Forbidden");
                            return .halt;
                        }
                    }

                    // Build file path
                    const file_path = if (path.len == 0)
                        try std.fs.path.join(ctx.allocator, &.{ options.root, options.index })
                    else
                        try std.fs.path.join(ctx.allocator, &.{ options.root, path });
                    defer ctx.allocator.free(file_path);

                    // Try to serve file
                    ctx.file(file_path) catch |err| {
                        switch (err) {
                            error.FileNotFound => {
                                if (options.fallthrough) {
                                    return .continue_chain;
                                } else {
                                    ctx.status(.not_found);
                                    try ctx.text("File not found");
                                    return .halt;
                                }
                            },
                            else => {
                                ctx.status(.internal_server_error);
                                try ctx.text("Internal server error");
                                return .halt;
                            },
                        }
                    };

                    // Set cache headers
                    if (options.max_age) |max_age| {
                        const cache_control = try std.fmt.allocPrint(ctx.allocator, "public, max-age={d}", .{max_age});
                        defer ctx.allocator.free(cache_control);
                        try ctx.setHeader("Cache-Control", cache_control);
                    }

                    // File was successfully served
                    return .halt;
                }
            }.handler,
        };
    }
};

/// Authentication middleware
pub const auth = struct {
    pub const BearerOptions = struct {
        realm: []const u8 = "Protected",
        verify: *const fn (token: []const u8) bool,
        // Optional: extract user info from token
        extract_user: ?*const fn (token: []const u8) ?[]const u8 = null,
    };

    pub fn bearer(comptime options: BearerOptions) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context) anyerror!MiddlewareResult {
                    const auth_header = ctx.header("authorization") orelse {
                        ctx.status(.unauthorized);
                        const realm_header = try std.fmt.allocPrint(ctx.allocator, "Bearer realm=\"{s}\"", .{options.realm});
                        defer ctx.allocator.free(realm_header);
                        try ctx.setHeader("WWW-Authenticate", realm_header);
                        try ctx.json(.{ .@"error" = "Authentication required" });
                        return .halt;
                    };

                    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
                        ctx.status(.unauthorized);
                        try ctx.json(.{ .@"error" = "Invalid authentication format" });
                        return .halt;
                    }

                    const token = auth_header[7..]; // Skip "Bearer "

                    if (!options.verify(token)) {
                        ctx.status(.unauthorized);
                        try ctx.json(.{ .@"error" = "Invalid token" });
                        return .halt;
                    }

                    // Store the token in locals for later use
                    try ctx.setLocal("auth_token", token);

                    // Optionally extract and store user info
                    if (options.extract_user) |extract_fn| {
                        if (extract_fn(token)) |user_info| {
                            try ctx.setLocal("user", user_info);
                        }
                    }

                    return .continue_chain;
                }
            }.handler,
        };
    }
};

test "middleware stack" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const TestMiddleware = struct {
        fn middleware1(ctx: *Context) !MiddlewareResult {
            try ctx.setLocalNoCopy("m1", "called");
            return .continue_chain;
        }

        fn middleware2(ctx: *Context) !MiddlewareResult {
            try ctx.setLocalNoCopy("m2", "called");
            return .continue_chain;
        }

        fn finalHandler(ctx: *Context) !void {
            try ctx.text("done");
        }
    };

    const middlewares = [_]Middleware{
        Middleware{ .handler = TestMiddleware.middleware1 },
        Middleware{ .handler = TestMiddleware.middleware2 },
    };

    const stack = MiddlewareStack(&middlewares);

    var request = Request.init(allocator);
    defer request.deinit();

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    try stack.handle(&ctx, TestMiddleware.finalHandler);

    try testing.expectEqualStrings("called", ctx.local("m1").?);
    try testing.expectEqualStrings("called", ctx.local("m2").?);
    try testing.expectEqualStrings("done", ctx.response.body.?);
}

test "middleware halt functionality" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const TestMiddleware = struct {
        fn middleware1(ctx: *Context) !MiddlewareResult {
            try ctx.setLocalNoCopy("m1", "called");
            return .continue_chain;
        }

        fn haltingMiddleware(ctx: *Context) !MiddlewareResult {
            try ctx.setLocalNoCopy("halt", "stopped");
            try ctx.text("halted");
            return .halt;
        }

        fn shouldNotRun(ctx: *Context) !MiddlewareResult {
            try ctx.setLocalNoCopy("should_not_run", "called");
            return .continue_chain;
        }

        fn finalHandler(ctx: *Context) !void {
            try ctx.text("final");
        }
    };

    const middlewares = [_]Middleware{
        Middleware{ .handler = TestMiddleware.middleware1 },
        Middleware{ .handler = TestMiddleware.haltingMiddleware },
        Middleware{ .handler = TestMiddleware.shouldNotRun },
    };

    const stack = MiddlewareStack(&middlewares);

    var request = Request.init(allocator);
    defer request.deinit();

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    try stack.handle(&ctx, TestMiddleware.finalHandler);

    // First middleware should have run
    try testing.expectEqualStrings("called", ctx.local("m1").?);
    // Halting middleware should have run
    try testing.expectEqualStrings("stopped", ctx.local("halt").?);
    // Third middleware should NOT have run
    try testing.expect(ctx.local("should_not_run") == null);
    // Final handler should NOT have run (halted before it)
    try testing.expectEqualStrings("halted", ctx.response.body.?);
}

test "JSON body parser middleware - valid JSON" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request = Request.init(allocator);
    defer request.deinit();
    request.body = try allocator.dupe(u8, "{\"name\":\"test\",\"value\":42}");
    try request.headers.set("content-type", "application/json");

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    const json_middleware = bodyParser.json(.{});
    const result = try json_middleware.handler(&ctx);

    try testing.expect(result == .continue_chain);
    try testing.expectEqualStrings("{\"name\":\"test\",\"value\":42}", ctx.local("json_body").?);
}

test "JSON body parser middleware - invalid JSON" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request = Request.init(allocator);
    defer request.deinit();
    request.body = try allocator.dupe(u8, "{invalid json syntax");
    try request.headers.set("content-type", "application/json");

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    const json_middleware = bodyParser.json(.{});
    const result = try json_middleware.handler(&ctx);

    try testing.expect(result == .halt);
    try testing.expect(ctx.response.status == .bad_request);
}

test "JSON body parser middleware - empty body" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request = Request.init(allocator);
    defer request.deinit();
    request.body = null;

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    const json_middleware = bodyParser.json(.{});
    const result = try json_middleware.handler(&ctx);

    try testing.expect(result == .continue_chain);
    try testing.expect(ctx.local("json_body") == null);
}

test "CORS middleware" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test regular request
    {
        var request = Request.init(allocator);
        defer request.deinit();
        request.method = .GET;

        var ctx = Context.init(allocator, request);
        defer ctx.deinit();

        const cors_middleware = cors.default();
        const result = try cors_middleware.handler(&ctx);

        try testing.expect(result == .continue_chain);
        try testing.expectEqualStrings("*", ctx.response.headers.get("Access-Control-Allow-Origin").?);
    }

    // Test OPTIONS preflight request
    {
        var request = Request.init(allocator);
        defer request.deinit();
        request.method = .OPTIONS;

        var ctx = Context.init(allocator, request);
        defer ctx.deinit();

        const cors_middleware = cors.default();
        const result = try cors_middleware.handler(&ctx);

        try testing.expect(result == .halt);
        try testing.expect(ctx.response.status == .no_content);
        try testing.expectEqualStrings("*", ctx.response.headers.get("Access-Control-Allow-Origin").?);
    }
}
