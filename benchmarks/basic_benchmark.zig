const std = @import("std");
const h3z = @import("h3z");

const BenchmarkConfig = struct {
    num_requests: u32 = 10000,
    concurrency: u32 = 100,
    warmup_requests: u32 = 1000,
};

const BenchmarkResult = struct {
    requests_per_second: f64,
    avg_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    total_time_ms: f64,
    memory_usage_mb: f64,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("Starting H3Z Benchmarks", .{});
    std.log.info("======================", .{});

    const config = BenchmarkConfig{
        .num_requests = 50000,
        .concurrency = 200,
        .warmup_requests = 5000,
    };

    // JSON Response Benchmark
    {
        std.log.info("\n1. JSON Response Benchmark", .{});
        const result = try benchmarkJsonResponse(allocator, config);
        printBenchmarkResult("JSON Response", result);
    }

    // Route Parameter Benchmark
    {
        std.log.info("\n2. Route Parameter Benchmark", .{});
        const result = try benchmarkRouteParams(allocator, config);
        printBenchmarkResult("Route Parameters", result);
    }

    // Middleware Stack Benchmark
    {
        std.log.info("\n3. Middleware Stack Benchmark", .{});
        const result = try benchmarkMiddleware(allocator, config);
        printBenchmarkResult("Middleware Stack", result);
    }

    // Memory Allocation Benchmark
    {
        std.log.info("\n4. Memory Usage Benchmark", .{});
        try benchmarkMemoryUsage(allocator, config);
    }

    std.log.info("\nBenchmarks completed!", .{});
}

fn benchmarkJsonResponse(allocator: std.mem.Allocator, config: BenchmarkConfig) !BenchmarkResult {
    var app = h3z.createApp(allocator, .{});
    defer app.deinit();

    const JsonHandler = struct {
        fn handle(ctx: *h3z.Context) !void {
            try ctx.json(.{
                .message = "Hello, H3Z!",
                .timestamp = std.time.timestamp(),
                .data = .{
                    .id = 12345,
                    .name = "Benchmark Test",
                    .values = .{ 1, 2, 3, 4, 5 },
                },
            });
        }
    };

    try app.get("/api/test", JsonHandler.handle);

    return benchmarkApp(&app, "/api/test", .GET, null, config);
}

fn benchmarkRouteParams(allocator: std.mem.Allocator, config: BenchmarkConfig) !BenchmarkResult {
    var app = h3z.createApp(allocator, .{});
    defer app.deinit();

    const ParamHandler = struct {
        fn handle(ctx: *h3z.Context) !void {
            const user_id = ctx.param("user_id") orelse "unknown";
            const post_id = ctx.param("post_id") orelse "unknown";

            try ctx.json(.{
                .user_id = user_id,
                .post_id = post_id,
                .message = "Route parameters extracted",
            });
        }
    };

    try app.get("/users/:user_id/posts/:post_id", ParamHandler.handle);

    return benchmarkApp(&app, "/users/123/posts/456", .GET, null, config);
}

fn benchmarkMiddleware(allocator: std.mem.Allocator, config: BenchmarkConfig) !BenchmarkResult {
    var app = h3z.createApp(allocator, .{});
    defer app.deinit();

    // Add multiple middleware
    try app.use(h3z.cors.default());
    try app.use(h3z.logger.middleware(.tiny));
    try app.use(createBenchmarkMiddleware());
    try app.use(createBenchmarkMiddleware());
    try app.use(createBenchmarkMiddleware());

    const MiddlewareHandler = struct {
        fn handle(ctx: *h3z.Context) !void {
            try ctx.json(.{
                .message = "Middleware benchmark",
                .middleware_count = 5,
            });
        }
    };

    try app.get("/middleware", MiddlewareHandler.handle);

    return benchmarkApp(&app, "/middleware", .GET, null, config);
}

fn createBenchmarkMiddleware() h3z.Middleware {
    return h3z.Middleware{
        .handler = struct {
            fn handle(ctx: *h3z.Context, next: h3z.NextFn) !void {
                // Simulate some middleware work
                try ctx.setLocal("benchmark", "middleware");
                try next(ctx);
            }
        }.handle,
    };
}

fn benchmarkApp(
    app: *h3z.App,
    path: []const u8,
    method: h3z.HttpMethod,
    body: ?[]const u8,
    config: BenchmarkConfig,
) !BenchmarkResult {
    var latencies = std.ArrayList(f64).init(std.heap.page_allocator);
    defer latencies.deinit();

    // Warmup
    std.log.info("Warming up with {} requests...", .{config.warmup_requests});
    var i: u32 = 0;
    while (i < config.warmup_requests) : (i += 1) {
        var response = try app.testRequest(method, path, body);
        response.deinit();
    }

    std.log.info("Running {} requests...", .{config.num_requests});

    const start_time = std.time.nanoTimestamp();

    i = 0;
    while (i < config.num_requests) : (i += 1) {
        const request_start = std.time.nanoTimestamp();

        var response = try app.testRequest(method, path, body);
        response.deinit();

        const request_end = std.time.nanoTimestamp();
        const latency_ms = @as(f64, @floatFromInt(request_end - request_start)) / 1_000_000.0;
        try latencies.append(latency_ms);

        if (i % 10000 == 0 and i > 0) {
            std.log.info("Completed {} requests...", .{i});
        }
    }

    const end_time = std.time.nanoTimestamp();
    const total_time_ms = @as(f64, @floatFromInt(end_time - start_time)) / 1_000_000.0;

    // Sort latencies for percentile calculation
    std.sort.insertion(f64, latencies.items, {}, comptime std.sort.asc(f64));

    const avg_latency = calculateAverage(latencies.items);
    const p50_latency = percentile(latencies.items, 50);
    const p95_latency = percentile(latencies.items, 95);
    const p99_latency = percentile(latencies.items, 99);

    const rps = @as(f64, @floatFromInt(config.num_requests)) / (total_time_ms / 1000.0);

    return BenchmarkResult{
        .requests_per_second = rps,
        .avg_latency_ms = avg_latency,
        .p50_latency_ms = p50_latency,
        .p95_latency_ms = p95_latency,
        .p99_latency_ms = p99_latency,
        .total_time_ms = total_time_ms,
        .memory_usage_mb = 0, // TODO: Implement memory tracking
    };
}

fn calculateAverage(values: []const f64) f64 {
    if (values.len == 0) return 0;

    var sum: f64 = 0;
    for (values) |value| {
        sum += value;
    }
    return sum / @as(f64, @floatFromInt(values.len));
}

fn percentile(sorted_values: []const f64, p: u8) f64 {
    if (sorted_values.len == 0) return 0;

    const index = (@as(f64, @floatFromInt(p)) / 100.0) * @as(f64, @floatFromInt(sorted_values.len - 1));
    const lower_index = @as(usize, @intFromFloat(@floor(index)));
    const upper_index = @min(lower_index + 1, sorted_values.len - 1);

    if (lower_index == upper_index) {
        return sorted_values[lower_index];
    }

    const weight = index - @as(f64, @floatFromInt(lower_index));
    return sorted_values[lower_index] * (1.0 - weight) + sorted_values[upper_index] * weight;
}

fn printBenchmarkResult(name: []const u8, result: BenchmarkResult) void {
    std.log.info("--- {} ---", .{name});
    std.log.info("Requests/sec:    {d:.2}", .{result.requests_per_second});
    std.log.info("Avg latency:     {d:.3}ms", .{result.avg_latency_ms});
    std.log.info("50th percentile: {d:.3}ms", .{result.p50_latency_ms});
    std.log.info("95th percentile: {d:.3}ms", .{result.p95_latency_ms});
    std.log.info("99th percentile: {d:.3}ms", .{result.p99_latency_ms});
    std.log.info("Total time:      {d:.2}ms", .{result.total_time_ms});
}

fn benchmarkMemoryUsage(allocator: std.mem.Allocator, config: BenchmarkConfig) !void {
    std.log.info("--- Memory Usage Benchmark ---", .{});

    var app = h3z.createApp(allocator, .{});
    defer app.deinit();

    const MemHandler = struct {
        fn handle(ctx: *h3z.Context) !void {
            // Create some temporary allocations
            const data = try ctx.allocator.alloc(u8, 1024);
            defer ctx.allocator.free(data);

            try ctx.json(.{
                .message = "Memory test",
                .size = data.len,
            });
        }
    };

    try app.get("/memory", MemHandler.handle);

    const initial_memory = getCurrentMemoryUsage();

    // Run requests and monitor memory
    var i: u32 = 0;
    while (i < config.num_requests / 10) : (i += 1) {
        var response = try app.testRequest(.GET, "/memory", null);
        response.deinit();

        if (i % 1000 == 0) {
            const current_memory = getCurrentMemoryUsage();
            std.log.info("After {} requests: {d:.2}MB", .{ i, @as(f64, @floatFromInt(current_memory)) / 1024.0 / 1024.0 });
        }
    }

    const final_memory = getCurrentMemoryUsage();
    const memory_growth = final_memory - initial_memory;

    std.log.info("Initial memory:  {d:.2}MB", .{@as(f64, @floatFromInt(initial_memory)) / 1024.0 / 1024.0});
    std.log.info("Final memory:    {d:.2}MB", .{@as(f64, @floatFromInt(final_memory)) / 1024.0 / 1024.0});
    std.log.info("Memory growth:   {d:.2}MB", .{@as(f64, @floatFromInt(memory_growth)) / 1024.0 / 1024.0});
}

fn getCurrentMemoryUsage() usize {
    // TODO: Implement actual memory usage tracking
    // This is a placeholder - in a real implementation, you'd use
    // platform-specific APIs to get memory usage
    return 0;
}

// Stress test with high concurrency
fn stressTest(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Stress Test ---", .{});

    var app = h3z.createApp(allocator, .{});
    defer app.deinit();

    const StressHandler = struct {
        fn handle(ctx: *h3z.Context) !void {
            // Simulate CPU-intensive work
            var sum: u64 = 0;
            var i: u32 = 0;
            while (i < 1000) : (i += 1) {
                sum +%= i;
            }

            try ctx.json(.{
                .result = sum,
                .timestamp = std.time.timestamp(),
            });
        }
    };

    try app.get("/stress", StressHandler.handle);

    const num_requests = 100000;
    const start_time = std.time.nanoTimestamp();

    var i: u32 = 0;
    while (i < num_requests) : (i += 1) {
        var response = try app.testRequest(.GET, "/stress", null);
        response.deinit();

        if (i % 10000 == 0 and i > 0) {
            const elapsed = std.time.nanoTimestamp() - start_time;
            const elapsed_sec = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
            const current_rps = @as(f64, @floatFromInt(i)) / elapsed_sec;
            std.log.info("Stress test: {} requests, {d:.0} req/s", .{ i, current_rps });
        }
    }

    const end_time = std.time.nanoTimestamp();
    const total_time = @as(f64, @floatFromInt(end_time - start_time)) / 1_000_000_000.0;
    const final_rps = @as(f64, @floatFromInt(num_requests)) / total_time;

    std.log.info("Stress test completed: {d:.0} req/s over {d:.2}s", .{ final_rps, total_time });
}
