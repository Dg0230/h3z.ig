const std = @import("std");
const h3z = @import("h3z");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create application
    var app = h3z.createApp(allocator, .{
        .host = "0.0.0.0",
        .port = 3000,
        .max_connections = 1000,
        .log_requests = true,
    });
    defer app.deinit();

    // Add global middleware
    try app.use(h3z.cors.default());
    try app.use(h3z.logger.default());

    // Add routes
    try app.get("/", indexHandler);
    try app.get("/health", healthHandler);
    try app.get("/api/users/:id", getUserHandler);
    try app.post("/api/users", createUserHandler);
    try app.put("/api/users/:id", updateUserHandler);
    try app.delete("/api/users/:id", deleteUserHandler);

    // API group with authentication
    var api_group = try app.group("/api/v1");
    try api_group.use(h3z.middleware.auth.bearer(.{
        .realm = "API",
        .verify = verifyToken,
    }));
    try api_group.get("/profile", profileHandler);
    try api_group.post("/logout", logoutHandler);

    // Static file serving
    try app.use(h3z.middleware.static.middleware(.{
        .root = "./public",
        .index = "index.html",
        .max_age = 3600,
    }));

    // Start server
    std.log.info("Starting H3Z example server...", .{});
    try app.listen();
}

fn indexHandler(ctx: *h3z.Context) !void {
    const response = .{
        .message = "Welcome to H3Z!",
        .version = h3z.VERSION,
        .timestamp = std.time.timestamp(),
    };

    try ctx.json(response);
}

fn healthHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{
        .status = "ok",
        .uptime = std.time.timestamp(),
        .memory = "todo", // In real app, get memory usage
    });
}

fn getUserHandler(ctx: *h3z.Context) !void {
    const user_id = ctx.param("id") orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Missing user ID" });
        return;
    };

    // Simulate database lookup
    if (std.mem.eql(u8, user_id, "1")) {
        try ctx.json(.{
            .id = user_id,
            .name = "John Doe",
            .email = "john@example.com",
            .created_at = "2024-01-01T00:00:00Z",
        });
    } else {
        ctx.status(.not_found);
        try ctx.json(.{ .@"error" = "User not found" });
    }
}

fn createUserHandler(ctx: *h3z.Context) !void {
    if (!ctx.hasJsonBody()) {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "JSON body required" });
        return;
    }

    const UserData = struct {
        name: []const u8,
        email: []const u8,
    };

    const user_data = ctx.bodyJson(UserData) catch {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Invalid JSON data" });
        return;
    };

    // Simulate user creation
    ctx.status(.created);
    try ctx.json(.{
        .id = "123",
        .name = user_data.name,
        .email = user_data.email,
        .created_at = "2024-01-01T12:00:00Z",
    });
}

fn updateUserHandler(ctx: *h3z.Context) !void {
    const user_id = ctx.param("id") orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Missing user ID" });
        return;
    };

    if (!ctx.hasJsonBody()) {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "JSON body required" });
        return;
    }

    const UserUpdateData = struct {
        name: ?[]const u8 = null,
        email: ?[]const u8 = null,
    };

    const update_data = ctx.bodyJson(UserUpdateData) catch {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Invalid JSON data" });
        return;
    };

    // Simulate user update
    try ctx.json(.{
        .id = user_id,
        .name = update_data.name orelse "John Doe",
        .email = update_data.email orelse "john@example.com",
        .updated_at = "2024-01-01T12:00:00Z",
    });
}

fn deleteUserHandler(ctx: *h3z.Context) !void {
    const user_id = ctx.param("id") orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Missing user ID" });
        return;
    };

    // Simulate user deletion
    ctx.status(.no_content);
    _ = user_id; // Use the parameter to avoid unused variable warning
}

fn profileHandler(ctx: *h3z.Context) !void {
    const user_id = ctx.local("user_id") orelse "unknown";

    try ctx.json(.{
        .id = user_id,
        .name = "Authenticated User",
        .email = "user@example.com",
        .role = "user",
    });
}

fn logoutHandler(ctx: *h3z.Context) !void {
    // In a real app, invalidate the token
    try ctx.json(.{ .message = "Logged out successfully" });
}

fn verifyToken(token: []const u8) bool {
    // Simple token verification for demo
    return std.mem.eql(u8, token, "valid-token-123");
}
