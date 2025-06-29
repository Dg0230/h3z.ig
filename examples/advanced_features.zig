const std = @import("std");
const h3z = @import("h3z");

// Advanced H3Z features demonstration
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = h3z.createApp(allocator, .{
        .host = "0.0.0.0",
        .port = 3002,
        .max_connections = 2000,
        .buffer_size = 16384,
        .tcp_nodelay = true,
        .tcp_keepalive = true,
    });
    defer app.deinit();

    // Advanced middleware composition
    try setupAdvancedMiddleware(&app);

    // RESTful API design
    try setupRestApiRoutes(&app);

    // Real-time features
    try setupRealtimeRoutes(&app);

    // File upload/download
    try setupFileRoutes(&app);

    // WebSocket-like streaming
    try setupStreamingRoutes(&app);

    std.log.info("🚀 H3Z Advanced Features Server starting on port 3002", .{});
    std.log.info("Features: REST API, File Handling, Streaming, Advanced Middleware", .{});

    try app.listen();
}

fn setupAdvancedMiddleware(app: *h3z.App) !void {
    // Custom request validation middleware
    const validationMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                // Validate Content-Length for POST requests
                if (ctx.isPost() or ctx.isPut()) {
                    const content_length = ctx.request.contentLength();
                    if (content_length == null or content_length.? > 10 * 1024 * 1024) { // 10MB limit
                        ctx.status(.payload_too_large);
                        try ctx.json(.{ .@"error" = "Request body too large (max 10MB)" });
                        return;
                    }
                }

                // Validate User-Agent
                if (ctx.userAgent() == null) {
                    try ctx.setHeader("X-Warning", "No User-Agent provided");
                }

                try next(ctx);
            }
        }.handle,
    };

    // Performance monitoring middleware
    const performanceMiddleware = h3z.Middleware{
        .handler = struct {
            var request_counter = std.atomic.Value(u64).init(0);
            var total_response_time = std.atomic.Value(u64).init(0);

            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const start_time = std.time.nanoTimestamp();
                const request_id = request_counter.fetchAdd(1, .monotonic);

                try next(ctx);

                const end_time = std.time.nanoTimestamp();
                const duration_ns = end_time - start_time;
                const duration_ms = duration_ns / 1_000_000;

                _ = total_response_time.fetchAdd(@intCast(duration_ns), .monotonic);

                // Add performance headers
                const duration_str = try std.fmt.allocPrint(ctx.allocator, "{}ms", .{duration_ms});
                defer ctx.allocator.free(duration_str);

                const request_id_str = try std.fmt.allocPrint(ctx.allocator, "{}", .{request_id});
                defer ctx.allocator.free(request_id_str);

                try ctx.setHeader("X-Response-Time", duration_str);
                try ctx.setHeader("X-Request-ID", request_id_str);

                // Log slow requests
                if (duration_ms > 100) {
                    std.log.warn("Slow request: {} {} took {}ms", .{ ctx.method().toString(), ctx.path(), duration_ms });
                }
            }
        }.handle,
    };

    // Content negotiation middleware
    const contentNegotiationMiddleware = h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                const accept_header = ctx.header("accept") orelse "application/json";

                // Store preferred content type
                if (std.mem.indexOf(u8, accept_header, "application/xml") != null) {
                    try ctx.setLocal("content_type", "xml");
                } else if (std.mem.indexOf(u8, accept_header, "text/csv") != null) {
                    try ctx.setLocal("content_type", "csv");
                } else {
                    try ctx.setLocal("content_type", "json");
                }

                try next(ctx);
            }
        }.handle,
    };

    try app.use(validationMiddleware);
    try app.use(performanceMiddleware);
    try app.use(contentNegotiationMiddleware);
    try app.use(h3z.cors.middleware(.{
        .origin = "https://example.com",
        .credentials = true,
        .max_age = 86400,
    }));
}

fn setupRestApiRoutes(app: *h3z.App) !void {
    // Users API with full CRUD operations
    var users_api = try app.group("/api/v1/users");

    try users_api.get("/", listUsersHandler);
    try users_api.get("/:id", getUserHandler);
    try users_api.post("/", createUserHandler);
    try users_api.put("/:id", updateUserHandler);
    try users_api.patch("/:id", patchUserHandler);
    try users_api.delete("/:id", deleteUserHandler);

    // Search and filtering
    try users_api.get("/search", searchUsersHandler);
    try users_api.get("/:id/posts", getUserPostsHandler);

    // Batch operations
    try users_api.post("/batch", batchCreateUsersHandler);
    try users_api.delete("/batch", batchDeleteUsersHandler);
}

fn setupRealtimeRoutes(app: *h3z.App) !void {
    var realtime_api = try app.group("/api/realtime");

    try realtime_api.get("/events", eventsStreamHandler);
    try realtime_api.post("/notify", notifyHandler);
    try realtime_api.get("/status", realtimeStatusHandler);
}

fn setupFileRoutes(app: *h3z.App) !void {
    var files_api = try app.group("/api/files");

    try files_api.post("/upload", fileUploadHandler);
    try files_api.get("/:id/download", fileDownloadHandler);
    try files_api.get("/:id/info", fileInfoHandler);
    try files_api.delete("/:id", deleteFileHandler);

    // Bulk operations
    try files_api.post("/upload/multiple", multipleFileUploadHandler);
    try files_api.get("/download/archive", downloadArchiveHandler);
}

fn setupStreamingRoutes(app: *h3z.App) !void {
    var streaming_api = try app.group("/api/stream");

    try streaming_api.get("/data", dataStreamHandler);
    try streaming_api.get("/logs", logStreamHandler);
    try streaming_api.get("/metrics", metricsStreamHandler);
}

// REST API Handlers
fn listUsersHandler(ctx: *h3z.Context) !void {
    const page = try ctx.query("page") orelse "1";
    const limit = try ctx.query("limit") orelse "10";
    const sort = try ctx.query("sort") orelse "id";

    defer if (page) |p| ctx.allocator.free(p);
    defer if (limit) |l| ctx.allocator.free(l);
    defer if (sort) |s| ctx.allocator.free(s);

    const page_num = std.fmt.parseInt(u32, page.?, 10) catch 1;
    const limit_num = std.fmt.parseInt(u32, limit.?, 10) catch 10;

    // Simulate database query with pagination
    var users = std.ArrayList(@TypeOf(.{
        .id = @as(u32, 0),
        .name = @as([]const u8, ""),
        .email = @as([]const u8, ""),
        .created_at = @as([]const u8, ""),
    })).init(ctx.allocator);
    defer users.deinit();

    var i: u32 = (page_num - 1) * limit_num + 1;
    const max_i = i + limit_num;
    while (i < max_i) : (i += 1) {
        const user_name = try std.fmt.allocPrint(ctx.allocator, "User {}", .{i});
        const user_email = try std.fmt.allocPrint(ctx.allocator, "user{}@example.com", .{i});

        try users.append(.{
            .id = i,
            .name = user_name,
            .email = user_email,
            .created_at = "2024-01-01T00:00:00Z",
        });
    }

    try ctx.json(.{
        .data = users.items,
        .pagination = .{
            .page = page_num,
            .limit = limit_num,
            .total = 1000, // Simulated total
            .sort = sort.?,
        },
        .meta = .{
            .response_time_ms = ctx.processingTime(),
            .api_version = "v1",
        },
    });
}

fn createUserHandler(ctx: *h3z.Context) !void {
    const CreateUserRequest = struct {
        name: []const u8,
        email: []const u8,
        age: ?u32 = null,
        preferences: ?struct {
            theme: []const u8 = "light",
            language: []const u8 = "en",
        } = null,
    };

    const user_data = ctx.bodyJson(CreateUserRequest) catch |err| {
        ctx.status(.bad_request);
        try ctx.json(.{
            .@"error" = "Invalid JSON data",
            .details = @errorName(err),
        });
        return;
    };

    // Validate required fields
    if (user_data.name.len == 0 or user_data.email.len == 0) {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Name and email are required" });
        return;
    }

    // Simulate user creation with ID generation
    const user_id = std.crypto.random.int(u32);

    ctx.status(.created);
    try ctx.json(.{
        .id = user_id,
        .name = user_data.name,
        .email = user_data.email,
        .age = user_data.age,
        .preferences = user_data.preferences,
        .created_at = "2024-01-01T12:00:00Z",
        .updated_at = "2024-01-01T12:00:00Z",
    });
}

fn batchCreateUsersHandler(ctx: *h3z.Context) !void {
    const BatchCreateRequest = struct {
        users: []const struct {
            name: []const u8,
            email: []const u8,
            age: ?u32 = null,
        },
    };

    const batch_data = ctx.bodyJson(BatchCreateRequest) catch |err| {
        ctx.status(.bad_request);
        try ctx.json(.{
            .@"error" = "Invalid batch data",
            .details = @errorName(err),
        });
        return;
    };

    if (batch_data.users.len > 100) {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Batch size limited to 100 users" });
        return;
    }

    var created_users = std.ArrayList(@TypeOf(.{
        .id = @as(u32, 0),
        .name = @as([]const u8, ""),
        .email = @as([]const u8, ""),
        .age = @as(?u32, null),
    })).init(ctx.allocator);
    defer created_users.deinit();

    for (batch_data.users) |user| {
        const user_id = std.crypto.random.int(u32);
        try created_users.append(.{
            .id = user_id,
            .name = user.name,
            .email = user.email,
            .age = user.age,
        });
    }

    ctx.status(.created);
    try ctx.json(.{
        .created = created_users.items,
        .count = created_users.items.len,
        .batch_id = std.crypto.random.int(u64),
    });
}

// File handling
fn fileUploadHandler(ctx: *h3z.Context) !void {
    const content_type = ctx.request.contentType() orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Content-Type required for file upload" });
        return;
    };

    if (!std.mem.startsWith(u8, content_type, "multipart/form-data")) {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Expected multipart/form-data" });
        return;
    }

    const body = ctx.bodyText() orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "No file data received" });
        return;
    };

    // Simulate file processing
    const file_id = std.crypto.random.int(u64);
    const file_size = body.len;

    ctx.status(.created);
    try ctx.json(.{
        .file_id = file_id,
        .filename = "uploaded_file.bin",
        .size = file_size,
        .content_type = "application/octet-stream",
        .upload_time = std.time.timestamp(),
        .checksum = "sha256:abcd1234...", // Simulated checksum
    });
}

// Real-time features
fn eventsStreamHandler(ctx: *h3z.Context) !void {
    try ctx.setHeader("Content-Type", "text/event-stream");
    try ctx.setHeader("Cache-Control", "no-cache");
    try ctx.setHeader("Connection", "keep-alive");

    // Simulate Server-Sent Events
    var events = std.ArrayList(u8).init(ctx.allocator);
    defer events.deinit();

    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const event_data = try std.fmt.allocPrint(ctx.allocator, "data: {{\"id\": {}, \"message\": \"Event {}\", \"timestamp\": {}}}\n\n", .{ i, i, std.time.timestamp() });
        defer ctx.allocator.free(event_data);

        try events.appendSlice(event_data);
    }

    try ctx.setHeader("Content-Length", try std.fmt.allocPrint(ctx.allocator, "{}", .{events.items.len}));
    ctx.response.body = try ctx.allocator.dupe(u8, events.items);
    ctx.response._body_owned = true;
}

fn metricsStreamHandler(ctx: *h3z.Context) !void {
    const content_type = ctx.local("content_type") orelse "json";

    if (std.mem.eql(u8, content_type, "csv")) {
        try ctx.setHeader("Content-Type", "text/csv");
        try ctx.text("timestamp,cpu_usage,memory_usage,requests_per_second\n" ++
            "1642680000,45.2,78.5,1250\n" ++
            "1642680060,47.1,79.2,1280\n" ++
            "1642680120,43.8,77.9,1200\n");
    } else {
        try ctx.json(.{
            .metrics = .{
                .cpu_usage = 45.2,
                .memory_usage = 78.5,
                .requests_per_second = 1250,
                .active_connections = 156,
                .response_time_p95 = 12.5,
            },
            .timestamp = std.time.timestamp(),
            .server_info = .{
                .version = h3z.VERSION,
                .uptime_seconds = 3600,
                .total_requests = 125000,
            },
        });
    }
}

// Additional handlers...
fn searchUsersHandler(ctx: *h3z.Context) !void {
    const query = try ctx.query("q") orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Search query 'q' parameter required" });
        return;
    };
    defer ctx.allocator.free(query.?);

    // Simulate search results
    try ctx.json(.{
        .query = query.?,
        .results = .{
            .{ .id = 1, .name = "John Doe", .email = "john@example.com" },
            .{ .id = 2, .name = "Jane Smith", .email = "jane@example.com" },
        },
        .total_results = 2,
        .search_time_ms = ctx.processingTime(),
    });
}

fn getUserHandler(ctx: *h3z.Context) !void {
    const user_id = ctx.param("id") orelse {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "User ID required" });
        return;
    };

    const id = std.fmt.parseInt(u32, user_id, 10) catch {
        ctx.status(.bad_request);
        try ctx.json(.{ .@"error" = "Invalid user ID format" });
        return;
    };

    if (id == 404) {
        ctx.status(.not_found);
        try ctx.json(.{ .@"error" = "User not found" });
        return;
    }

    try ctx.json(.{
        .id = id,
        .name = "John Doe",
        .email = "john@example.com",
        .profile = .{
            .bio = "Software developer",
            .location = "San Francisco, CA",
            .website = "https://johndoe.dev",
        },
        .stats = .{
            .posts_count = 42,
            .followers_count = 1337,
            .following_count = 256,
        },
        .created_at = "2024-01-01T00:00:00Z",
        .last_active = "2024-01-15T10:30:00Z",
    });
}

fn updateUserHandler(ctx: *h3z.Context) !void {
    // Similar to createUserHandler but with PUT semantics
    try ctx.json(.{ .message = "User updated successfully" });
}

fn patchUserHandler(ctx: *h3z.Context) !void {
    // Partial update with PATCH semantics
    try ctx.json(.{ .message = "User partially updated" });
}

fn deleteUserHandler(ctx: *h3z.Context) !void {
    ctx.status(.no_content);
}

fn getUserPostsHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .posts = .{}, .message = "User posts" });
}

fn batchDeleteUsersHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Batch delete completed" });
}

fn notifyHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Notification sent" });
}

fn realtimeStatusHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .status = "active", .connections = 42 });
}

fn fileDownloadHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "File download" });
}

fn fileInfoHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "File info" });
}

fn deleteFileHandler(ctx: *h3z.Context) !void {
    ctx.status(.no_content);
}

fn multipleFileUploadHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Multiple files uploaded" });
}

fn downloadArchiveHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Archive download" });
}

fn dataStreamHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Data stream" });
}

fn logStreamHandler(ctx: *h3z.Context) !void {
    try ctx.json(.{ .message = "Log stream" });
}
