const std = @import("std");

/// Resource management interface
pub fn ResourceManager(comptime T: type) type {
    return struct {
        const Self = @This();

        deinitFn: *const fn (ptr: *T) void,

        pub fn deinit(self: Self, ptr: *T) void {
            self.deinitFn(ptr);
        }
    };
}

/// RAII smart pointer for automatic resource cleanup
pub fn UniquePtr(comptime T: type) type {
    return struct {
        const Self = @This();

        ptr: ?*T,
        allocator: std.mem.Allocator,
        deinit_fn: ?*const fn (*T) void = null,

        /// Create from raw pointer with allocator
        pub fn init(allocator: std.mem.Allocator, ptr: *T) Self {
            return Self{
                .ptr = ptr,
                .allocator = allocator,
            };
        }

        /// Create with custom destructor
        pub fn initWithDeinit(allocator: std.mem.Allocator, ptr: *T, deinit_fn: *const fn (*T) void) Self {
            return Self{
                .ptr = ptr,
                .allocator = allocator,
                .deinit_fn = deinit_fn,
            };
        }

        /// Create from allocated memory
        pub fn create(allocator: std.mem.Allocator) !Self {
            const ptr = try allocator.create(T);
            return init(allocator, ptr);
        }

        /// Release ownership and return raw pointer
        pub fn release(self: *Self) ?*T {
            const ptr = self.ptr;
            self.ptr = null;
            return ptr;
        }

        /// Reset with new pointer
        pub fn reset(self: *Self, new_ptr: ?*T) void {
            if (self.ptr) |ptr| {
                if (self.deinit_fn) |deinit_fn| {
                    deinit_fn(ptr);
                }
                self.allocator.destroy(ptr);
            }
            self.ptr = new_ptr;
        }

        /// Get raw pointer (non-owning)
        pub fn get(self: *const Self) ?*T {
            return self.ptr;
        }

        /// Dereference (panics if null)
        pub fn deref(self: *const Self) *T {
            return self.ptr orelse @panic("Dereferencing null UniquePtr");
        }

        /// Check if pointer is valid
        pub fn isValid(self: *const Self) bool {
            return self.ptr != null;
        }

        /// Automatic cleanup on scope exit
        pub fn deinit(self: *Self) void {
            if (self.ptr) |ptr| {
                if (self.deinit_fn) |deinit_fn| {
                    deinit_fn(ptr);
                }
                self.allocator.destroy(ptr);
                self.ptr = null;
            }
        }
    };
}

/// Shared pointer with reference counting
pub fn SharedPtr(comptime T: type) type {
    return struct {
        const Self = @This();
        const RefCount = std.atomic.Value(u32);

        const ControlBlock = struct {
            ref_count: RefCount,
            ptr: *T,
            allocator: std.mem.Allocator,
            deinit_fn: ?*const fn (*T) void,

            fn init(allocator: std.mem.Allocator, ptr: *T, deinit_fn: ?*const fn (*T) void) !*ControlBlock {
                const control = try allocator.create(ControlBlock);
                control.* = ControlBlock{
                    .ref_count = RefCount.init(1),
                    .ptr = ptr,
                    .allocator = allocator,
                    .deinit_fn = deinit_fn,
                };
                return control;
            }

            fn addRef(self: *ControlBlock) void {
                _ = self.ref_count.fetchAdd(1, .monotonic);
            }

            fn release(self: *ControlBlock) void {
                const old_count = self.ref_count.fetchSub(1, .acq_rel);
                if (old_count == 1) {
                    // Last reference, clean up
                    if (self.deinit_fn) |deinit_fn| {
                        deinit_fn(self.ptr);
                    }
                    self.allocator.destroy(self.ptr);
                    self.allocator.destroy(self);
                }
            }

            fn getRefCount(self: *const ControlBlock) u32 {
                return self.ref_count.load(.monotonic);
            }
        };

        control: ?*ControlBlock,

        /// Create from raw pointer
        pub fn init(allocator: std.mem.Allocator, ptr: *T) !Self {
            const control = try ControlBlock.init(allocator, ptr, null);
            return Self{ .control = control };
        }

        /// Create with custom destructor
        pub fn initWithDeinit(allocator: std.mem.Allocator, ptr: *T, deinit_fn: *const fn (*T) void) !Self {
            const control = try ControlBlock.init(allocator, ptr, deinit_fn);
            return Self{ .control = control };
        }

        /// Create from allocated memory
        pub fn create(allocator: std.mem.Allocator) !Self {
            const ptr = try allocator.create(T);
            return try init(allocator, ptr);
        }

        /// Copy constructor (increases reference count)
        pub fn copy(self: *const Self) Self {
            if (self.control) |control| {
                control.addRef();
                return Self{ .control = control };
            }
            return Self{ .control = null };
        }

        /// Get raw pointer (non-owning)
        pub fn get(self: *const Self) ?*T {
            if (self.control) |control| {
                return control.ptr;
            }
            return null;
        }

        /// Dereference (panics if null)
        pub fn deref(self: *const Self) *T {
            if (self.control) |control| {
                return control.ptr;
            }
            @panic("Dereferencing null SharedPtr");
        }

        /// Check if pointer is valid
        pub fn isValid(self: *const Self) bool {
            return self.control != null;
        }

        /// Get current reference count
        pub fn useCount(self: *const Self) u32 {
            if (self.control) |control| {
                return control.getRefCount();
            }
            return 0;
        }

        /// Check if this is the only reference
        pub fn unique(self: *const Self) bool {
            return self.useCount() == 1;
        }

        /// Reset to null
        pub fn reset(self: *Self) void {
            if (self.control) |control| {
                control.release();
                self.control = null;
            }
        }

        /// Automatic cleanup (decreases reference count)
        pub fn deinit(self: *Self) void {
            self.reset();
        }
    };
}

/// Arena-based RAII allocator for request lifetime management
pub const ArenaManager = struct {
    arena: std.heap.ArenaAllocator,
    parent_allocator: std.mem.Allocator,

    pub fn init(parent_allocator: std.mem.Allocator) ArenaManager {
        return ArenaManager{
            .arena = std.heap.ArenaAllocator.init(parent_allocator),
            .parent_allocator = parent_allocator,
        };
    }

    pub fn allocator(self: *ArenaManager) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Get current memory usage
    pub fn bytesAllocated(self: *const ArenaManager) usize {
        return self.arena.queryCapacity();
    }

    /// Reset arena (frees all allocations)
    pub fn reset(self: *ArenaManager) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// Reset and free all memory
    pub fn resetAndFree(self: *ArenaManager) void {
        _ = self.arena.reset(.free_all);
    }

    /// Clean up arena
    pub fn deinit(self: *ArenaManager) void {
        self.arena.deinit();
    }
};

/// Stack-based allocator for small, temporary allocations
pub fn StackAllocator(comptime size: usize) type {
    return struct {
        const Self = @This();

        buffer: [size]u8,
        offset: usize = 0,

        pub fn init() Self {
            return Self{
                .buffer = undefined,
                .offset = 0,
            };
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
            return std.mem.Allocator{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                    .remap = remap,
                },
            };
        }

        fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, _: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));

            const align_val = @max(1, @intFromEnum(ptr_align));
            const adjust_off = std.mem.alignForward(usize, self.offset, align_val);
            const new_offset = adjust_off + len;

            if (new_offset > self.buffer.len) {
                return null; // Out of space
            }

            const result = self.buffer[adjust_off..new_offset];
            self.offset = new_offset;
            return result.ptr;
        }

        fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
            return false; // Cannot resize in stack allocator
        }

        fn free(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
            // No-op for stack allocator
        }

        fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
            return null; // Cannot remap in stack allocator
        }

        pub fn reset(self: *Self) void {
            self.offset = 0;
        }

        pub fn bytesUsed(self: *const Self) usize {
            return self.offset;
        }

        pub fn bytesRemaining(self: *const Self) usize {
            return self.buffer.len - self.offset;
        }
    };
}

// Tests
test "UniquePtr basic operations" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test creation and destruction
    {
        var ptr = try UniquePtr(u32).create(allocator);
        defer ptr.deinit();

        ptr.deref().* = 42;
        try testing.expect(ptr.deref().* == 42);
        try testing.expect(ptr.isValid());
    }

    // Test release
    {
        var ptr = try UniquePtr(u32).create(allocator);
        const raw = ptr.release();
        defer allocator.destroy(raw.?);

        try testing.expect(!ptr.isValid());
        raw.?.* = 123;
        try testing.expect(raw.?.* == 123);
    }
}

test "SharedPtr reference counting" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ptr1 = try SharedPtr(u32).create(allocator);
    defer ptr1.deinit();

    ptr1.deref().* = 42;
    try testing.expect(ptr1.useCount() == 1);
    try testing.expect(ptr1.unique());

    // Create second reference
    var ptr2 = ptr1.copy();
    defer ptr2.deinit();

    try testing.expect(ptr1.useCount() == 2);
    try testing.expect(ptr2.useCount() == 2);
    try testing.expect(!ptr1.unique());
    try testing.expect(ptr2.deref().* == 42);
}

test "ArenaManager" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const parent_allocator = gpa.allocator();

    var arena = ArenaManager.init(parent_allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    // Allocate some memory
    const slice1 = try alloc.alloc(u8, 100);
    const slice2 = try alloc.alloc(u32, 50);

    @memset(slice1, 0xAA);
    for (slice2) |*item| item.* = 0xBBBBBBBB;

    // Check memory is accessible
    try testing.expect(slice1[0] == 0xAA);
    try testing.expect(slice2[0] == 0xBBBBBBBB);

    // Reset should free all
    arena.reset();

    // Can allocate again after reset
    const slice3 = try alloc.alloc(u8, 200);
    @memset(slice3, 0xCC);
    try testing.expect(slice3[0] == 0xCC);
}

test "StackAllocator" {
    const testing = std.testing;

    var stack = StackAllocator(1024).init();
    const alloc = stack.allocator();

    // Test allocation
    const slice1 = try alloc.alloc(u8, 100);
    const slice2 = try alloc.alloc(u32, 25); // 100 bytes

    try testing.expect(slice1.len == 100);
    try testing.expect(slice2.len == 25);
    try testing.expect(stack.bytesUsed() >= 200); // May have alignment padding

    // Test out of space
    const large_slice = alloc.alloc(u8, 2000);
    try testing.expect(std.meta.isError(large_slice));

    // Test reset
    stack.reset();
    try testing.expect(stack.bytesUsed() == 0);

    // Can allocate again after reset
    const slice3 = try alloc.alloc(u8, 100);
    try testing.expect(slice3.len == 100);
}
