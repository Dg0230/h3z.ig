const std = @import("std");

/// Buffer size categories for different use cases
pub const BufferSize = enum(u32) {
    small = 1024, // 1KB - headers, small responses
    medium = 4096, // 4KB - typical requests
    large = 8192, // 8KB - file uploads, large responses
    xlarge = 32768, // 32KB - streaming, chunked transfer

    pub fn fromSize(size: usize) BufferSize {
        if (size <= 1024) return .small;
        if (size <= 4096) return .medium;
        if (size <= 8192) return .large;
        return .xlarge;
    }

    pub fn bytes(self: BufferSize) u32 {
        return @intFromEnum(self);
    }
};

/// Managed buffer with automatic cleanup
pub const ManagedBuffer = struct {
    data: []u8,
    size: BufferSize,
    pool: *BufferPool,
    in_use: bool = true,

    pub fn deinit(self: *ManagedBuffer) void {
        if (self.in_use) {
            self.pool.release(self);
        }
    }

    pub fn bytes(self: *const ManagedBuffer) []u8 {
        return self.data;
    }

    pub fn capacity(self: *const ManagedBuffer) usize {
        return self.data.len;
    }
};

/// Pool statistics for monitoring
pub const PoolStats = struct {
    total_allocated: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_released: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    current_in_use: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    peak_usage: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Per-size category stats
    allocated_by_size: [4]std.atomic.Value(u32) = [_]std.atomic.Value(u32){
        std.atomic.Value(u32).init(0),
        std.atomic.Value(u32).init(0),
        std.atomic.Value(u32).init(0),
        std.atomic.Value(u32).init(0),
    },

    pub fn recordAllocation(self: *PoolStats, size: BufferSize) void {
        _ = self.total_allocated.fetchAdd(1, .monotonic);
        const current = self.current_in_use.fetchAdd(1, .monotonic) + 1;

        // Update peak usage atomically
        var peak = self.peak_usage.load(.monotonic);
        while (current > peak) {
            const result = self.peak_usage.cmpxchgWeak(peak, current, .monotonic, .monotonic);
            if (result == null) {
                break; // Successfully updated
            } else {
                peak = result.?; // Update our local copy and try again
            }
        }

        const size_index: usize = switch (size) {
            .small => 0,
            .medium => 1,
            .large => 2,
            .xlarge => 3,
        };
        _ = self.allocated_by_size[size_index].fetchAdd(1, .monotonic);
    }

    pub fn recordRelease(self: *PoolStats) void {
        _ = self.total_released.fetchAdd(1, .monotonic);
        _ = self.current_in_use.fetchSub(1, .monotonic);
    }
};

/// High-performance buffer pool with size-based categories
pub const BufferPool = struct {
    // Separate pools for each buffer size
    pools: [4]std.ArrayList([]u8),

    // Pool configuration
    max_buffers_per_size: u32,
    grow_threshold: f32,
    shrink_threshold: f32,

    // Thread safety
    mutex: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,

    // Monitoring
    stats: PoolStats = .{},

    const DEFAULT_MAX_BUFFERS = 100;
    const DEFAULT_GROW_THRESHOLD = 0.8; // Grow when 80% used
    const DEFAULT_SHRINK_THRESHOLD = 0.3; // Shrink when 30% used

    /// Initialize buffer pool with configuration
    pub fn init(allocator: std.mem.Allocator, config: struct {
        max_buffers_per_size: u32 = DEFAULT_MAX_BUFFERS,
        grow_threshold: f32 = DEFAULT_GROW_THRESHOLD,
        shrink_threshold: f32 = DEFAULT_SHRINK_THRESHOLD,
    }) BufferPool {
        var pools: [4]std.ArrayList([]u8) = undefined;

        inline for (&pools) |*pool| {
            pool.* = std.ArrayList([]u8).init(allocator);
        }

        return BufferPool{
            .pools = pools,
            .max_buffers_per_size = config.max_buffers_per_size,
            .grow_threshold = config.grow_threshold,
            .shrink_threshold = config.shrink_threshold,
            .allocator = allocator,
        };
    }

    /// Clean up all buffers and pools
    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (&self.pools) |*pool| {
            for (pool.items) |buffer| {
                self.allocator.free(buffer);
            }
            pool.deinit();
        }
    }

    /// Acquire a buffer of the specified size
    pub fn acquire(self: *BufferPool, size: BufferSize) !ManagedBuffer {
        self.mutex.lock();
        defer self.mutex.unlock();

        const pool_index = self.getSizeIndex(size);
        var pool = &self.pools[pool_index];

        // Try to reuse existing buffer
        if (pool.items.len > 0) {
            const buffer = pool.orderedRemove(pool.items.len - 1);
            self.stats.recordAllocation(size);
            return ManagedBuffer{
                .data = buffer,
                .size = size,
                .pool = self,
            };
        }

        // Allocate new buffer if pool is empty
        const buffer = try self.allocator.alloc(u8, size.bytes());
        self.stats.recordAllocation(size);

        return ManagedBuffer{
            .data = buffer,
            .size = size,
            .pool = self,
        };
    }

    /// Acquire buffer based on requested size (auto-categorization)
    pub fn acquireForSize(self: *BufferPool, requested_size: usize) !ManagedBuffer {
        const size = BufferSize.fromSize(requested_size);
        return self.acquire(size);
    }

    /// Release buffer back to pool
    pub fn release(self: *BufferPool, buffer: *ManagedBuffer) void {
        if (!buffer.in_use) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const pool_index = self.getSizeIndex(buffer.size);
        var pool = &self.pools[pool_index];

        // Return to pool if not at capacity
        if (pool.items.len < self.max_buffers_per_size) {
            // Clear buffer data for security
            @memset(buffer.data, 0);

            pool.append(buffer.data) catch {
                // If append fails, just free the buffer
                self.allocator.free(buffer.data);
            };
        } else {
            // Pool at capacity, free the buffer
            self.allocator.free(buffer.data);
        }

        buffer.in_use = false;
        self.stats.recordRelease();

        // Check if we should shrink pools (call without lock)
        // Calculate utilization inline to avoid deadlock
        var total_buffers: u32 = 0;
        var total_capacity: u32 = 0;

        for (self.pools) |p| {
            total_buffers += @intCast(p.items.len);
            total_capacity += self.max_buffers_per_size;
        }

        const util = if (total_capacity == 0) 0.0 else @as(f32, @floatFromInt(total_buffers)) / @as(f32, @floatFromInt(total_capacity));

        if (util < self.shrink_threshold) {
            // Shrink pools to reduce memory usage
            for (&self.pools) |*p| {
                const target_size = @max(1, p.items.len / 2);

                // Free excess buffers
                if (target_size < p.items.len) {
                    for (p.items[target_size..]) |buf| {
                        self.allocator.free(buf);
                    }
                    p.shrinkRetainingCapacity(target_size);
                }
            }
        }
    }

    /// Get current pool utilization (0.0 to 1.0)
    pub fn utilization(self: *BufferPool) f32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total_buffers: u32 = 0;
        var total_capacity: u32 = 0;

        for (self.pools) |pool| {
            total_buffers += @intCast(pool.items.len);
            total_capacity += self.max_buffers_per_size;
        }

        if (total_capacity == 0) return 0.0;
        return @as(f32, @floatFromInt(total_buffers)) / @as(f32, @floatFromInt(total_capacity));
    }

    /// Get pool statistics
    pub fn getStats(self: *const BufferPool) PoolStats {
        return self.stats;
    }

    /// Print pool status for debugging
    pub fn printStats(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const stats = self.stats;
        std.log.info("BufferPool Statistics:", .{});
        std.log.info("  Total allocated: {}", .{stats.total_allocated.load(.monotonic)});
        std.log.info("  Total released: {}", .{stats.total_released.load(.monotonic)});
        std.log.info("  Currently in use: {}", .{stats.current_in_use.load(.monotonic)});
        std.log.info("  Peak usage: {}", .{stats.peak_usage.load(.monotonic)});
        std.log.info("  Pool utilization: {d:.1%}", .{self.utilization()});

        const sizes = [_]BufferSize{ .small, .medium, .large, .xlarge };
        inline for (sizes, 0..) |size, i| {
            const count = self.pools[i].items.len;
            const allocated = stats.allocated_by_size[i].load(.monotonic);
            std.log.info("  {s} ({} bytes): {} in pool, {} allocated", .{ @tagName(size), size.bytes(), count, allocated });
        }
    }

    /// Force garbage collection of unused buffers
    pub fn gc(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (&self.pools) |*pool| {
            // Keep only the most recently used buffers
            const keep_count = @min(pool.items.len, self.max_buffers_per_size / 2);

            // Free excess buffers
            for (pool.items[keep_count..]) |buffer| {
                self.allocator.free(buffer);
            }

            pool.shrinkRetainingCapacity(keep_count);
        }
    }

    // Private helper methods

    fn getSizeIndex(self: *BufferPool, size: BufferSize) usize {
        _ = self;
        return switch (size) {
            .small => 0,
            .medium => 1,
            .large => 2,
            .xlarge => 3,
        };
    }
};

// Tests
test "buffer pool basic operations" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = BufferPool.init(allocator, .{});
    defer pool.deinit();

    // Test buffer acquisition
    var buffer = try pool.acquire(.medium);
    defer buffer.deinit();

    try testing.expect(buffer.capacity() == 4096);
    try testing.expect(buffer.in_use == true);

    // Test size-based acquisition
    var small_buffer = try pool.acquireForSize(512);
    defer small_buffer.deinit();

    try testing.expect(small_buffer.size == .small);
}

test "buffer pool reuse" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = BufferPool.init(allocator, .{});
    defer pool.deinit();

    // Acquire and release buffer
    {
        var buffer = try pool.acquire(.small);
        const ptr = buffer.data.ptr;
        buffer.deinit();

        // Acquire again, should reuse the same buffer
        var buffer2 = try pool.acquire(.small);
        defer buffer2.deinit();

        try testing.expect(buffer2.data.ptr == ptr);
    }
}

test "buffer pool statistics" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = BufferPool.init(allocator, .{});
    defer pool.deinit();

    const stats_before = pool.getStats();

    var buffer = try pool.acquire(.large);
    defer buffer.deinit();

    const stats_after = pool.getStats();

    try testing.expect(stats_after.current_in_use.load(.monotonic) ==
        stats_before.current_in_use.load(.monotonic) + 1);
}
