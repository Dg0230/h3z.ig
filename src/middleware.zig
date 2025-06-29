const std = @import("std");
const Context = @import("context.zig").Context;

/// Next function type for middleware chain
pub const NextFn = *const fn (ctx: *Context) anyerror!void;

/// Middleware function type
pub const MiddlewareFn = *const fn (ctx: *Context, next: NextFn) anyerror!void;

/// Middleware wrapper
pub const Middleware = struct {
    handler: MiddlewareFn,

    pub fn call(self: Middleware, ctx: *Context, next: NextFn) anyerror!void {
        return self.handler(ctx, next);
    }
};

/// Compile-time middleware stack builder
pub fn MiddlewareStack(comptime middlewares: []const Middleware) type {
    return struct {
        const Self = @This();

        /// Handle request through middleware stack
        pub fn handle(ctx: *Context, final_handler: NextFn) anyerror!void {
            return handleAtIndex(ctx, 0, final_handler);
        }

        /// Handle middleware at specific index
        fn handleAtIndex(ctx: *Context, comptime index: usize, final_handler: NextFn) anyerror!void {
            if (ctx.isAborted()) return;

            if (index >= middlewares.len) {
                return final_handler(ctx);
            }

            const middleware = middlewares[index];

            // Simple dummy next function for now
            const next = struct {
                fn call(context: *Context) anyerror!void {
                    _ = context;
                    // In a real implementation, this would chain to the next middleware
                }
            }.call;

            return middleware.call(ctx, next);
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
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
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
                        return; // Don't call next for OPTIONS
                    }

                    try next(ctx);
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
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    const start_time = std.time.milliTimestamp();

                    try next(ctx);

                    const duration = std.time.milliTimestamp() - start_time;
                    const method = ctx.method().toString();
                    const path = ctx.path();
                    const status = @intFromEnum(ctx.response.status);
                    const user_agent = ctx.userAgent() orelse "-";
                    const ip = ctx.ip() orelse "unknown";

                    switch (format) {
                        .dev => {
                            const status_color = if (status >= 500) "\x1b[31m" // red
                                else if (status >= 400) "\x1b[33m" // yellow
                                else if (status >= 300) "\x1b[36m" // cyan
                                else "\x1b[32m"; // green

                            std.log.info("{s}{s} {s}\x1b[0m {s} - {d}ms", .{ status_color, method, @tagName(ctx.response.status), path, duration });
                        },
                        .short => {
                            std.log.info("{s} {s} {d} - {d}ms", .{ method, path, status, duration });
                        },
                        .tiny => {
                            std.log.info("{s} {s} {d}", .{ method, path, status });
                        },
                        .common => {
                            std.log.info("{s} - - [{d}] \"{s} {s}\" {d} -", .{ ip, std.time.timestamp(), method, path, status });
                        },
                        .combined => {
                            std.log.info("{s} - - [{d}] \"{s} {s}\" {d} - \"{s}\"", .{ ip, std.time.timestamp(), method, path, status, user_agent });
                        },
                    }
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

    pub fn json(options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    if (ctx.request.body) |body| {
                        if (body.len > options.limit) {
                            ctx.status(.payload_too_large);
                            try ctx.text("Request body too large");
                            return;
                        }

                        if (options.strict and !ctx.hasJsonBody()) {
                            ctx.status(.bad_request);
                            try ctx.text("Expected JSON content type");
                            return;
                        }
                    }

                    try next(ctx);
                }
            }.handler,
        };
    }

    pub fn urlencoded(options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    if (ctx.request.body) |body| {
                        if (body.len > options.limit) {
                            ctx.status(.payload_too_large);
                            try ctx.text("Request body too large");
                            return;
                        }

                        if (options.strict and !ctx.request.isForm()) {
                            ctx.status(.bad_request);
                            try ctx.text("Expected form content type");
                            return;
                        }
                    }

                    try next(ctx);
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

    const RateLimiter = struct {
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
                // First request from this IP
                self.requests.put(ip, RequestInfo{
                    .count = 1,
                    .reset_time = reset_time,
                }) catch return true; // Allow on allocation error
                return true;
            }
        }
    };

    // Global rate limiter instance (in real implementation, this should be configurable)
    var global_limiter: ?RateLimiter = null;
    var limiter_mutex: std.Thread.Mutex = .{};

    pub fn middleware(options: Options) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    const ip = ctx.ip() orelse "unknown";

                    // Initialize global limiter if needed
                    limiter_mutex.lock();
                    if (global_limiter == null) {
                        global_limiter = RateLimiter.init(ctx.allocator);
                    }
                    limiter_mutex.unlock();

                    if (!global_limiter.?.checkLimit(ip, options)) {
                        ctx.status(.too_many_requests);
                        try ctx.setHeader("Retry-After", "900"); // 15 minutes
                        try ctx.text(options.message);
                        return;
                    }

                    try next(ctx);
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
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    if (!ctx.isGet() and !ctx.isMethod(.HEAD)) {
                        try next(ctx);
                        return;
                    }

                    var path = ctx.path();

                    // Remove leading slash
                    if (path.len > 0 and path[0] == '/') {
                        path = path[1..];
                    }

                    // Check for dotfiles
                    if (!options.dotfiles and std.mem.indexOf(u8, path, "/.") != null) {
                        if (options.fallthrough) {
                            try next(ctx);
                            return;
                        } else {
                            ctx.status(.forbidden);
                            try ctx.text("Forbidden");
                            return;
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
                                    try next(ctx);
                                    return;
                                } else {
                                    ctx.status(.not_found);
                                    try ctx.text("File not found");
                                    return;
                                }
                            },
                            else => {
                                ctx.status(.internal_server_error);
                                try ctx.text("Internal server error");
                                return;
                            },
                        }
                    };

                    // Set cache headers
                    if (options.max_age) |max_age| {
                        const cache_control = try std.fmt.allocPrint(ctx.allocator, "public, max-age={d}", .{max_age});
                        defer ctx.allocator.free(cache_control);
                        try ctx.setHeader("Cache-Control", cache_control);
                    }
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
    };

    pub fn bearer(comptime options: BearerOptions) Middleware {
        return Middleware{
            .handler = struct {
                fn handler(ctx: *Context, next: NextFn) anyerror!void {
                    const auth_header = ctx.header("authorization") orelse {
                        ctx.status(.unauthorized);
                        const realm_header = try std.fmt.allocPrint(ctx.allocator, "Bearer realm=\"{s}\"", .{options.realm});
                        defer ctx.allocator.free(realm_header);
                        try ctx.setHeader("WWW-Authenticate", realm_header);
                        try ctx.json(.{ .@"error" = "Authentication required" });
                        return;
                    };

                    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
                        ctx.status(.unauthorized);
                        try ctx.json(.{ .@"error" = "Invalid authentication format" });
                        return;
                    }

                    const token = auth_header[7..]; // Skip "Bearer "

                    if (!options.verify(token)) {
                        ctx.status(.unauthorized);
                        try ctx.json(.{ .@"error" = "Invalid token" });
                        return;
                    }

                    try next(ctx);
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
        fn middleware1(ctx: *Context, next: NextFn) !void {
            try ctx.setLocal("m1", "called");
            try next(ctx);
        }

        fn middleware2(ctx: *Context, next: NextFn) !void {
            try ctx.setLocal("m2", "called");
            try next(ctx);
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

    var request = @import("http/request.zig").Request.init(allocator);
    defer request.deinit();

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    try stack.handle(&ctx, TestMiddleware.finalHandler);

    try testing.expectEqualStrings("called", ctx.local("m1").?);
    try testing.expectEqualStrings("called", ctx.local("m2").?);
    try testing.expectEqualStrings("done", ctx.response.body.?);
}
