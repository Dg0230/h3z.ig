const std = @import("std");

/// A string-to-string map that owns its keys and values
pub fn StringMap(comptime name: []const u8) type {
    return struct {
        const Self = @This();

        /// Internal map that owns both keys and values
        map: std.StringHashMap([]const u8),
        allocator: std.mem.Allocator,

        // Store the map name for debugging purposes
        const map_name: []const u8 = name;

        /// Initialize a new StringMap
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .map = std.StringHashMap([]const u8).init(allocator),
                .allocator = allocator,
            };
        }

        /// Deinitialize the map, freeing all keys and values
        pub fn deinit(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            self.map.deinit();
        }

        /// Put a key-value pair into the map, taking ownership of the strings
        pub fn putOwned(self: *Self, key: []const u8, value: []const u8) !void {
            // Check if key already exists
            if (self.map.getPtr(key)) |existing_value| {
                // Free the old value
                self.allocator.free(existing_value.*);
                // Duplicate the new value
                const value_copy = try self.allocator.dupe(u8, value);
                existing_value.* = value_copy;
            } else {
                // Duplicate both key and value
                const key_copy = try self.allocator.dupe(u8, key);
                const value_copy = try self.allocator.dupe(u8, value);
                try self.map.put(key_copy, value_copy);
            }
        }

        /// Put a key-value pair into the map without taking ownership
        pub fn putBorrowed(self: *Self, key: []const u8, value: []const u8) !void {
            try self.putOwned(key, value);
        }

        /// Get a value by key
        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            return self.map.get(key);
        }

        /// Check if the map contains a key
        pub fn contains(self: *const Self, key: []const u8) bool {
            return self.map.contains(key);
        }

        /// Remove a key-value pair, freeing the memory
        pub fn remove(self: *Self, key: []const u8) bool {
            if (self.map.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                return true;
            }
            return false;
        }

        /// Get the number of entries in the map
        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        /// Get an iterator over the key-value pairs
        pub fn iterator(self: *const Self) Iterator {
            return .{ .inner = self.map.iterator() };
        }

        /// Iterator type for the map
        pub const Iterator = struct {
            inner: std.StringHashMap([]const u8).Iterator,

            /// Get the next key-value pair
            pub fn next(self: *Iterator) ?struct { []const u8, []const u8 } {
                if (self.inner.next()) |entry| {
                    return .{ entry.key_ptr.*, entry.value_ptr.* };
                }
                return null;
            }
        };
    };
}
