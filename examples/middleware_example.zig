const std = @import("std");
const h3z = @import("h3z");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = h3z.createApp(allocator, .{
        .host = "0.0.0.0",
        .port = 3001,
    });
    defer app.deinit();

    // Request timing middleware
    const timingMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const start_time = std.time.milliTimestamp();

                try next(ctx);

                const duration = std.time.milliTimestamp() - start_time;
                const duration_str = try std.fmt.allocPrint(ctx.allocator, "{}ms", .{duration});
                defer ctx.allocator.free(duration_str);

                try ctx.setHeader("X-Response-Time", duration_str);
            }
        }.handle,
    };

    // Request ID middleware
    const requestIdMiddleware = h3z.Middleware{
        .handler = struct {
            var counter = std.atomic.Value(u64).init(0);

            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const request_id = counter.fetchAdd(1, .monotonic);
                const id_str = try std.fmt.allocPrint(ctx.allocator, "req-{}", .{request_id});
                defer ctx.allocator.free(id_str);

                try ctx.setLocal("request_id", id_str);
                try ctx.setHeader("X-Request-ID", id_str);

                try next(ctx);
            }
        }.handle,
    };

    // Security headers middleware
    const securityMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                try ctx.setHeader("X-Content-Type-Options", "nosniff");
                try ctx.setHeader("X-Frame-Options", "DENY");
                try ctx.setHeader("X-XSS-Protection", "1; mode=block");
                try ctx.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

                try next(ctx);
            }
        }.handle,
    };

    // Global middleware
    try app.use(timingMiddleware);
    try app.use(requestIdMiddleware);
    try app.use(securityMiddleware);
    try app.use(h3z.cors.default());
    try app.use(h3z.logger.default());

    // Routes
    try app.get("/", homeHandler);
    try app.get("/middleware-info", middlewareInfoHandler);

    // API routes with additional middleware
    var api_group = try app.group("/api");
    try api_group.use(h3z.rateLimit.middleware(.{
        .window_ms = 60 * 1000, // 1 minute
        .max_requests = 100,
    }));
    try api_group.get("/status", statusHandler);
    try api_group.get("/protected", protectedHandler);

    std.log.info("Middleware example server starting on port 3001", .{});
    try app.listen();
}

fn homeHandler(ctx: *h3z.Context) !void {
    const request_id = ctx.local("request_id") orelse "unknown";

    try ctx.html(
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\    <title>H3Z Middleware Example</title>
        \\    <style>
        \\        body { font-family: Arial, sans-serif; margin: 40px; }
        \\        .container { max-width: 800px; margin: 0 auto; }
        \\        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        \\        .info { margin: 20px 0; padding: 15px; background: #e7f3ff; border-radius: 5px; }
        \\        .endpoint { margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #007acc; }
        \\        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <div class="header">
        \\            <h1>🚀 H3Z Middleware Example</h1>
        \\            <p>This server demonstrates various middleware features</p>
        \\        </div>
        \\        
        \\        <div class="info">
        \\            <h3>📋 Request Information</h3>
        \\            <p><strong>Request ID:</strong> <code>{s}</code></p>
        \\            <p><strong>User Agent:</strong> <code>{s}</code></p>
        \\            <p><strong>IP Address:</strong> <code>{s}</code></p>
        \\        </div>
        \\        
        \\        <h3>🔌 Available Endpoints</h3>
        \\        
        \\        <div class="endpoint">
        \\            <strong>GET /middleware-info</strong>
        \\            <p>Shows detailed middleware information</p>
        \\        </div>
        \\        
        \\        <div class="endpoint">
        \\            <strong>GET /api/status</strong>
        \\            <p>API status with rate limiting</p>
        \\        </div>
        \\        
        \\        <div class="endpoint">
        \\            <strong>GET /api/protected</strong>
        \\            <p>Protected endpoint requiring authentication</p>
        \\        </div>
        \\        
        \\        <h3>🛡️ Active Middleware</h3>
        \\        <ul>
        \\            <li><strong>Timing:</strong> Measures request duration</li>
        \\            <li><strong>Request ID:</strong> Assigns unique ID to each request</li>
        \\            <li><strong>Security Headers:</strong> Adds security-related headers</li>
        \\            <li><strong>CORS:</strong> Cross-origin resource sharing</li>
        \\            <li><strong>Logger:</strong> Request logging</li>
        \\            <li><strong>Rate Limiting:</strong> API endpoint protection</li>
        \\        </ul>
        \\    </div>
        \\</body>
        \\</html>
    , .{ request_id, ctx.userAgent() orelse "Unknown", ctx.ip() orelse "Unknown" });
}

fn middlewareInfoHandler(ctx: *h3z.Context) !void {
    const request_id = ctx.local("request_id") orelse "unknown";

    var response_headers = std.ArrayList([]const u8).init(ctx.allocator);
    defer response_headers.deinit();

    var header_iter = ctx.response.headers.iterator();
    while (header_iter.next()) |entry| {
        const header_info = try std.fmt.allocPrint(ctx.allocator, "{s}: {s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        try response_headers.append(header_info);
    }

    try ctx.json(.{
        .request = .{
            .id = request_id,
            .method = ctx.method().toString(),
            .path = ctx.path(),
            .user_agent = ctx.userAgent(),
            .ip = ctx.ip(),
            .secure = ctx.isSecure(),
        },
        .middleware = .{
            .timing_enabled = true,
            .request_id_enabled = true,
            .security_headers_enabled = true,
            .cors_enabled = true,
            .logging_enabled = true,
        },
        .headers = .{
            .request_headers = ctx.request.headers.count(),
            .response_headers = ctx.response.headers.count(),
        },
        .performance = .{
            .processing_time_ms = ctx.processingTime(),
        },
    });
}

fn statusHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{
        .status = "ok",
        .message = "API is running",
        .timestamp = std.time.timestamp(),
        .request_id = ctx.local("request_id"),
        .middleware = .{
            .rate_limiting = "active",
            .max_requests_per_minute = 100,
        },
    });
}

fn protectedHandler(ctx: *h3z.Context) !void {
    const auth_header = ctx.header("authorization");

    if (auth_header == null or !std.mem.startsWith(u8, auth_header.?, "Bearer ")) {
        ctx.status(.unauthorized);
        try ctx.json(.{
            .@"error" = "Authentication required",
            .message = "Please provide a valid Bearer token",
            .request_id = ctx.local("request_id"),
        });
        return;
    }

    const token = auth_header.?[7..]; // Skip "Bearer "

    if (!std.mem.eql(u8, token, "valid-token-123")) {
        ctx.status(.unauthorized);
        try ctx.json(.{
            .@"error" = "Invalid token",
            .message = "The provided token is not valid",
            .request_id = ctx.local("request_id"),
        });
        return;
    }

    try ctx.json(.{
        .message = "Access granted to protected resource",
        .user = .{
            .id = "user-123",
            .name = "Authenticated User",
        },
        .request_id = ctx.local("request_id"),
        .timestamp = std.time.timestamp(),
    });
}
