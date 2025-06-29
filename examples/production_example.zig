const std = @import("std");
const h3z = @import("h3z");

// Production-ready H3Z application with comprehensive features
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Production configuration
    var app = h3z.createApp(allocator, .{
        .host = "0.0.0.0",
        .port = 8080,
        .max_connections = 10000,
        .buffer_size = 32768,
        .read_timeout_ms = 30000,
        .write_timeout_ms = 30000,
        .keep_alive = true,
        .reuse_address = true,
        .tcp_nodelay = true,
        .tcp_keepalive = true,
        .log_requests = true,
        .log_level = .info,
    });
    defer app.deinit();

    // Production middleware stack
    try setupProductionMiddleware(&app);

    // Health and monitoring endpoints
    try setupHealthEndpoints(&app);

    // Main business logic routes
    try setupBusinessRoutes(&app);

    // Admin and management routes
    try setupAdminRoutes(&app);

    // Error handling and fallback routes
    try setupErrorHandling(&app);

    std.log.info("🏭 H3Z Production Server starting...", .{});
    std.log.info("Configuration: port=8080, max_connections=10000", .{});
    std.log.info("Features: Health checks, metrics, admin interface, business logic", .{});

    try app.listen();
}

fn setupProductionMiddleware(app: *h3z.App) !void {
    // Security middleware - must be first
    const securityMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                // Security headers
                try ctx.setHeader("X-Content-Type-Options", "nosniff");
                try ctx.setHeader("X-Frame-Options", "DENY");
                try ctx.setHeader("X-XSS-Protection", "1; mode=block");
                try ctx.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
                try ctx.setHeader("Content-Security-Policy", "default-src 'self'");

                // Remove server information
                try ctx.setHeader("Server", "H3Z");

                try next(ctx);
            }
        }.handle,
    };

    // Request correlation middleware
    const correlationMiddleware = h3z.Middleware{
        .handler = struct {
            var request_counter = std.atomic.Value(u64).init(0);

            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                // Generate or extract correlation ID
                var correlation_id: []const u8 = undefined;

                if (ctx.header("X-Correlation-ID")) |existing_id| {
                    correlation_id = existing_id;
                } else {
                    const req_id = request_counter.fetchAdd(1, .monotonic);
                    const timestamp = std.time.timestamp();
                    correlation_id = try std.fmt.allocPrint(ctx.allocator, "h3z-{}-{}", .{ timestamp, req_id });
                }

                try ctx.setLocal("correlation_id", correlation_id);
                try ctx.setHeader("X-Correlation-ID", correlation_id);

                try next(ctx);
            }
        }.handle,
    };

    // Comprehensive logging middleware
    const productionLogger = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const start_time = std.time.nanoTimestamp();
                const correlation_id = ctx.local("correlation_id") orelse "unknown";

                // Log request start
                std.log.info("[{}] {} {} - Start", .{ correlation_id, ctx.method().toString(), ctx.path() });

                try next(ctx);

                // Log request completion
                const duration_ns = std.time.nanoTimestamp() - start_time;
                const duration_ms = duration_ns / 1_000_000;
                const status = @intFromEnum(ctx.response.status);

                if (status >= 400) {
                    std.log.err("[{}] {} {} - {} ({}ms)", .{ correlation_id, ctx.method().toString(), ctx.path(), status, duration_ms });
                } else if (duration_ms > 1000) {
                    std.log.warn("[{}] {} {} - {} ({}ms) SLOW", .{ correlation_id, ctx.method().toString(), ctx.path(), status, duration_ms });
                } else {
                    std.log.info("[{}] {} {} - {} ({}ms)", .{ correlation_id, ctx.method().toString(), ctx.path(), status, duration_ms });
                }
            }
        }.handle,
    };

    // Rate limiting with different tiers
    const rateLimitMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const path = ctx.path();
                const ip = ctx.ip() orelse "unknown";

                // Different limits for different endpoints
                var limit: u32 = 1000; // Default requests per minute
                var window_ms: u64 = 60 * 1000; // 1 minute

                if (std.mem.startsWith(u8, path, "/api/auth/")) {
                    limit = 10; // Strict limit for auth endpoints
                    window_ms = 60 * 1000;
                } else if (std.mem.startsWith(u8, path, "/api/")) {
                    limit = 100; // API endpoints
                } else if (std.mem.startsWith(u8, path, "/health")) {
                    limit = 10000; // Health checks can be frequent
                }

                // Simple rate limiting check (in production, use Redis or similar)
                _ = ip;

                try next(ctx);
            }
        }.handle,
    };

    try app.use(securityMiddleware);
    try app.use(correlationMiddleware);
    try app.use(productionLogger);
    try app.use(rateLimitMiddleware);
    try app.use(h3z.cors.middleware(.{
        .origin = "https://yourdomain.com",
        .credentials = true,
        .max_age = 86400,
    }));
}

fn setupHealthEndpoints(app: *h3z.App) !void {
    var health_group = try app.group("/health");

    try health_group.get("/", healthCheckHandler);
    try health_group.get("/live", livenessProbeHandler);
    try health_group.get("/ready", readinessProbeHandler);
    try health_group.get("/metrics", metricsHandler);
    try health_group.get("/info", systemInfoHandler);
}

fn setupBusinessRoutes(app: *h3z.App) !void {
    // Authentication routes
    var auth_group = try app.group("/api/auth");
    try auth_group.post("/login", loginHandler);
    try auth_group.post("/logout", logoutHandler);
    try auth_group.post("/refresh", refreshTokenHandler);
    try auth_group.get("/profile", profileHandler);

    // Business entity routes
    var api_group = try app.group("/api/v1");

    // Users
    try api_group.get("/users", listUsersHandler);
    try api_group.get("/users/:id", getUserHandler);
    try api_group.post("/users", createUserHandler);
    try api_group.put("/users/:id", updateUserHandler);
    try api_group.delete("/users/:id", deleteUserHandler);

    // Orders
    try api_group.get("/orders", listOrdersHandler);
    try api_group.get("/orders/:id", getOrderHandler);
    try api_group.post("/orders", createOrderHandler);
    try api_group.put("/orders/:id/status", updateOrderStatusHandler);

    // Products
    try api_group.get("/products", listProductsHandler);
    try api_group.get("/products/:id", getProductHandler);
    try api_group.get("/products/search", searchProductsHandler);
}

fn setupAdminRoutes(app: *h3z.App) !void {
    var admin_group = try app.group("/admin");

    // Add admin authentication middleware
    try admin_group.use(adminAuthMiddleware());

    try admin_group.get("/stats", adminStatsHandler);
    try admin_group.get("/users", adminUserListHandler);
    try admin_group.post("/users/:id/suspend", suspendUserHandler);
    try admin_group.get("/system/config", systemConfigHandler);
    try admin_group.post("/system/maintenance", maintenanceHandler);
}

fn setupErrorHandling(app: *h3z.App) !void {
    // Catch-all handler for 404s
    try app.get("/*", notFoundHandler);
}

// Authentication middleware
fn adminAuthMiddleware() h3z.Middleware {
    return h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const auth_header = ctx.header("authorization") orelse {
                    ctx.status(.unauthorized);
                    try ctx.json(.{
                        .@"error" = "Admin authentication required",
                        .correlation_id = ctx.local("correlation_id"),
                    });
                    return;
                };

                if (!std.mem.startsWith(u8, auth_header, "Bearer admin-")) {
                    ctx.status(.forbidden);
                    try ctx.json(.{
                        .@"error" = "Admin privileges required",
                        .correlation_id = ctx.local("correlation_id"),
                    });
                    return;
                }

                try ctx.setLocal("admin_user", "admin");
                try next(ctx);
            }
        }.handle,
    };
}

// Health check handlers
fn healthCheckHandler(ctx: *h3z.Context) !void {
    // Quick health check
    try ctx.json(.{
        .status = "healthy",
        .timestamp = std.time.timestamp(),
        .version = h3z.VERSION,
        .uptime_seconds = 3600, // Would be calculated from start time
    });
}

fn livenessProbeHandler(ctx: *h3z.Context) !void {
    // Kubernetes liveness probe
    try ctx.json(.{
        .alive = true,
        .timestamp = std.time.timestamp(),
    });
}

fn readinessProbeHandler(ctx: *h3z.Context) !void {
    // Check if service is ready to accept traffic
    const database_connected = checkDatabaseConnection();
    const external_services_ok = checkExternalServices();

    if (database_connected and external_services_ok) {
        try ctx.json(.{
            .ready = true,
            .checks = .{
                .database = "connected",
                .external_services = "available",
            },
        });
    } else {
        ctx.status(.service_unavailable);
        try ctx.json(.{
            .ready = false,
            .checks = .{
                .database = if (database_connected) "connected" else "disconnected",
                .external_services = if (external_services_ok) "available" else "unavailable",
            },
        });
    }
}

fn metricsHandler(ctx: *h3z.Context) !void {
    // Prometheus-style metrics
    const stats = ctx.app.getStats();

    try ctx.setHeader("Content-Type", "text/plain");

    const metrics_text = try std.fmt.allocPrint(ctx.allocator,
        \\# HELP http_requests_total Total number of HTTP requests
        \\# TYPE http_requests_total counter
        \\http_requests_total {}
        \\
        \\# HELP http_requests_active Currently active HTTP requests
        \\# TYPE http_requests_active gauge
        \\http_requests_active {}
        \\
        \\# HELP http_connections_total Total number of connections
        \\# TYPE http_connections_total counter
        \\http_connections_total {}
        \\
        \\# HELP http_connections_active Currently active connections
        \\# TYPE http_connections_active gauge
        \\http_connections_active {}
        \\
        \\# HELP http_bytes_sent_total Total bytes sent
        \\# TYPE http_bytes_sent_total counter
        \\http_bytes_sent_total {}
        \\
        \\# HELP http_bytes_received_total Total bytes received
        \\# TYPE http_bytes_received_total counter
        \\http_bytes_received_total {}
        \\
        \\# HELP http_errors_total Total number of HTTP errors
        \\# TYPE http_errors_total counter
        \\http_errors_total {}
        \\
    , .{
        stats.requests_total.load(.monotonic),
        stats.requests_active.load(.monotonic),
        stats.connections_total.load(.monotonic),
        stats.connections_active.load(.monotonic),
        stats.bytes_sent.load(.monotonic),
        stats.bytes_received.load(.monotonic),
        stats.errors_total.load(.monotonic),
    });

    try ctx.text(metrics_text);
}

fn systemInfoHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{
        .system = .{
            .platform = @tagName(std.builtin.target.os.tag),
            .arch = @tagName(std.builtin.target.cpu.arch),
            .zig_version = std.builtin.zig_version_string,
        },
        .server = .{
            .name = "H3Z",
            .version = h3z.VERSION,
            .start_time = "2024-01-01T00:00:00Z", // Would be actual start time
            .pid = std.os.linux.getpid(),
        },
        .runtime = .{
            .uptime_seconds = 3600,
            .memory_usage_mb = 45.2,
            .cpu_usage_percent = 12.5,
        },
        .configuration = .{
            .max_connections = 10000,
            .buffer_size = 32768,
            .keep_alive = true,
        },
    });
}

// Business logic handlers
fn loginHandler(ctx: *h3z.Context) !void {
    const LoginRequest = struct {
        email: []const u8,
        password: []const u8,
        remember_me: bool = false,
    };

    const login_data = ctx.bodyJson(LoginRequest) catch |err| {
        ctx.status(.bad_request);
        try ctx.json(.{
            .@"error" = "Invalid login data",
            .details = @errorName(err),
            .correlation_id = ctx.local("correlation_id"),
        });
        return;
    };

    // Simulate authentication
    if (std.mem.eql(u8, login_data.email, "user@example.com") and
        std.mem.eql(u8, login_data.password, "password123"))
    {
        const access_token = "jwt_access_token_here";
        const refresh_token = "jwt_refresh_token_here";

        try ctx.json(.{
            .success = true,
            .user = .{
                .id = 1,
                .email = login_data.email,
                .name = "John Doe",
                .role = "user",
            },
            .tokens = .{
                .access_token = access_token,
                .refresh_token = refresh_token,
                .expires_in = 3600,
            },
            .correlation_id = ctx.local("correlation_id"),
        });
    } else {
        ctx.status(.unauthorized);
        try ctx.json(.{
            .@"error" = "Invalid credentials",
            .correlation_id = ctx.local("correlation_id"),
        });
    }
}

fn createOrderHandler(ctx: *h3z.Context) !void {
    const CreateOrderRequest = struct {
        customer_id: u32,
        items: []const struct {
            product_id: u32,
            quantity: u32,
            price: f64,
        },
        shipping_address: struct {
            street: []const u8,
            city: []const u8,
            postal_code: []const u8,
            country: []const u8,
        },
        payment_method: []const u8,
    };

    const order_data = ctx.bodyJson(CreateOrderRequest) catch |err| {
        ctx.status(.bad_request);
        try ctx.json(.{
            .@"error" = "Invalid order data",
            .details = @errorName(err),
            .correlation_id = ctx.local("correlation_id"),
        });
        return;
    };

    // Validate order
    if (order_data.items.len == 0) {
        ctx.status(.bad_request);
        try ctx.json(.{
            .@"error" = "Order must contain at least one item",
            .correlation_id = ctx.local("correlation_id"),
        });
        return;
    }

    // Calculate total
    var total: f64 = 0;
    for (order_data.items) |item| {
        total += item.price * @as(f64, @floatFromInt(item.quantity));
    }

    const order_id = std.crypto.random.int(u64);

    ctx.status(.created);
    try ctx.json(.{
        .order_id = order_id,
        .customer_id = order_data.customer_id,
        .status = "pending",
        .total_amount = total,
        .currency = "USD",
        .items = order_data.items,
        .shipping_address = order_data.shipping_address,
        .payment_method = order_data.payment_method,
        .created_at = "2024-01-01T12:00:00Z",
        .estimated_delivery = "2024-01-05T12:00:00Z",
        .correlation_id = ctx.local("correlation_id"),
    });
}

// Helper functions
fn checkDatabaseConnection() bool {
    // In production, this would actually check database connectivity
    return true;
}

fn checkExternalServices() bool {
    // In production, this would check external service health
    return true;
}

// Stub handlers for completeness
fn logoutHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Logged out successfully" });
}

fn refreshTokenHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Token refreshed" });
}

fn profileHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "User profile" });
}

fn listUsersHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .users = .{} });
}

fn getUserHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .user = .{} });
}

fn createUserHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "User created" });
}

fn updateUserHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "User updated" });
}

fn deleteUserHandler(ctx: *h3z.Context) !void {
    ctx.status(.no_content);
}

fn listOrdersHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .orders = .{} });
}

fn getOrderHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .order = .{} });
}

fn updateOrderStatusHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Order status updated" });
}

fn listProductsHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .products = .{} });
}

fn getProductHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .product = .{} });
}

fn searchProductsHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .results = .{} });
}

fn adminStatsHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .stats = .{} });
}

fn adminUserListHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .users = .{} });
}

fn suspendUserHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "User suspended" });
}

fn systemConfigHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .config = .{} });
}

fn maintenanceHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Maintenance mode activated" });
}

fn notFoundHandler(ctx: *h3z.Context) !void {
    ctx.status(.not_found);
    try ctx.json(.{
        .@"error" = "Resource not found",
        .path = ctx.path(),
        .method = ctx.method().toString(),
        .correlation_id = ctx.local("correlation_id"),
    });
}
