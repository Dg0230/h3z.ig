const std = @import("std");
const Allocator = std.mem.Allocator;

/// Optimized HTTP headers implementation with support for multiple values per header
/// and case-insensitive header name lookups.
pub const Headers = struct {
    const HeaderMap = std.StringHashMapUnmanaged(HeaderValue);
    const HeaderList = std.ArrayListUnmanaged(HeaderEntry);

    map: HeaderMap = .{},
    list: HeaderList = .{},
    allocator: Allocator,

    const HeaderValue = struct {
        first_value: []const u8,
        extra_values: std.ArrayListUnmanaged([]const u8) = .{},
        owned: bool = false,

        pub fn deinit(self: *HeaderValue, allocator: Allocator) void {
            if (self.owned) {
                allocator.free(self.first_value);
            }
            // Free all extra values (all owned by this HeaderValue)
            for (self.extra_values.items) |value| {
                allocator.free(value);
            }
            self.extra_values.deinit(allocator);
        }

        /// Add an extra value to this header (takes ownership of the value)
        pub fn addExtraValue(self: *HeaderValue, allocator: Allocator, value: []const u8) !void {
            try self.extra_values.append(allocator, value);
        }

        pub fn getAllValues(self: *const HeaderValue) []const []const u8 {
            return self.extra_values.items;
        }
    };

    const HeaderEntry = struct {
        key: []const u8,
        value: []const u8, // Reference to the value owned by HeaderValue
        is_first: bool = true, // Whether this is the first value for this header
    };

    /// Initialize a new Headers instance
    pub fn init(allocator: Allocator) Headers {
        return .{
            .allocator = allocator,
        };
    }

    /// Deinitialize the headers, freeing all owned memory
    pub fn deinit(self: *Headers) void {
        // First, free all list entries (only the keys, as values are owned by HeaderValue)
        for (self.list.items) |entry| {
            // Free the key (always owned by the list entry)
            self.allocator.free(entry.key);
            // Values are owned by HeaderValue, so we don't free them here
        }

        // Then free all map entries (which own the values)
        var it = self.map.iterator();
        while (it.next()) |entry| {
            // Free the HeaderValue (which frees its first value and extra values)
            entry.value_ptr.deinit(self.allocator);
            // Free the lowercase key used in the map
            self.allocator.free(entry.key_ptr.*);
        }

        // Finally, free the containers themselves
        self.map.deinit(self.allocator);
        self.list.deinit(self.allocator);
    }

    /// Add a header (takes ownership of key and value)
    pub fn addOwned(self: *Headers, key: []const u8, value: []const u8) !void {
        // Create lowercase version of the key for case-insensitive comparison
        const lower_key = try self.dupeLower(key);
        defer self.allocator.free(lower_key);

        const gop = try self.map.getOrPut(self.allocator, lower_key);

        if (!gop.found_existing) {
            // New header - create owned copies of key and value
            const owned_key = try self.allocator.dupe(u8, key);
            const owned_lower_key = try self.dupeLower(owned_key);

            gop.key_ptr.* = owned_lower_key;
            gop.value_ptr.* = .{
                .first_value = value,
                .owned = true,
            };

            // Add to list with owned key
            try self.list.append(self.allocator, .{
                .key = owned_key,
                .value = value,
                .is_first = true,
            });
        } else {
            // Existing header - add as extra value
            if (gop.value_ptr.owned) {
                try gop.value_ptr.addExtraValue(self.allocator, value);

                // Add to list as non-first entry
                try self.list.append(self.allocator, .{
                    .key = key,
                    .value = value,
                    .is_first = false,
                });
            } else {
                // Convert to owned and add new value
                const first_value = try self.allocator.dupe(u8, gop.value_ptr.first_value);
                errdefer self.allocator.free(first_value);

                gop.value_ptr.* = .{
                    .first_value = first_value,
                    .owned = true,
                };

                // Update the first entry in the list to be owned
                for (self.list.items) |*entry| {
                    if (std.ascii.eqlIgnoreCase(entry.key, key) and entry.is_first) {
                        entry.value = first_value;
                        break;
                    }
                }

                // Add the new value
                try gop.value_ptr.addExtraValue(self.allocator, value);
                try self.list.append(self.allocator, .{
                    .key = key,
                    .value = value,
                    .is_first = false,
                });
            }
        }
    }

    /// Add a header (borrows key and value)
    pub fn addBorrowed(self: *Headers, key: []const u8, value: []const u8) !void {
        // Create lowercase version of the key for case-insensitive comparison
        const lower_key = try self.dupeLower(key);
        defer self.allocator.free(lower_key);

        // Check if we already have this header
        const gop = try self.map.getOrPut(self.allocator, lower_key);

        if (!gop.found_existing) {
            // New header - create owned copies of key and value
            const owned_key = try self.allocator.dupe(u8, key);
            const value_copy = try self.allocator.dupe(u8, value);

            const owned_lower_key = try self.dupeLower(owned_key);
            gop.key_ptr.* = owned_lower_key;
            gop.value_ptr.* = .{
                .first_value = value_copy,
                .owned = true,
            };

            // Add to list with owned key and reference to the value
            try self.list.append(self.allocator, .{
                .key = owned_key,
                .value = value_copy, // This is a reference to the owned value
                .is_first = true,
            });
        } else {
            // For existing header, add as extra value
            const value_copy = try self.allocator.dupe(u8, value);

            // Add the value to the header value (which takes ownership of it)
            try gop.value_ptr.addExtraValue(self.allocator, value_copy);

            // Create a copy of the key for the list entry
            const key_copy = try self.allocator.dupe(u8, gop.key_ptr.*);

            // Add to list with the copied key and reference to the value
            try self.list.append(self.allocator, .{
                .key = key_copy,
                .value = value_copy, // This is a reference to the owned value in HeaderValue
                .is_first = false,
            });
        }
    }

    /// Set a header, replacing any existing values
    pub fn set(self: *Headers, key: []const u8, value: []const u8) !void {
        // Create lowercase version of the key for case-insensitive comparison
        const lower_key = try self.dupeLower(key);
        defer self.allocator.free(lower_key);

        // Remove all existing entries for this header
        if (self.map.fetchRemove(lower_key)) |kv| {
            // Free the header value (which will free all its values)
            var header_value = kv.value;
            header_value.deinit(self.allocator);

            // Free the lowercase key used in the map
            self.allocator.free(kv.key);

            // Remove from list and free associated memory
            var i: usize = 0;
            while (i < self.list.items.len) {
                const entry = &self.list.items[i];
                if (std.ascii.eqlIgnoreCase(entry.key, key)) {
                    const removed = self.list.swapRemove(i);
                    self.allocator.free(removed.key);
                    if (!removed.is_first) {
                        // For non-first entries, we need to free the value
                        self.allocator.free(removed.value);
                    }
                } else {
                    i += 1;
                }
            }
        }

        // Add the new value
        try self.addBorrowed(key, value);
    }

    /// Get the first value for a header (case-insensitive)
    pub fn get(self: Headers, key: []const u8) ?[]const u8 {
        const lower_key = self.dupeLower(key) catch return null;
        defer self.allocator.free(lower_key);

        return if (self.map.get(lower_key)) |header| header.first_value else null;
    }

    /// Get all header values for a given key (case-insensitive)
    pub fn getValues(self: Headers, key: []const u8) ?[]const []const u8 {
        const lower_key = self.dupeLower(key) catch return null;
        defer self.allocator.free(lower_key);

        if (self.map.get(lower_key)) |header_value| {
            return header_value.getAllValues();
        }
        return null;
    }

    /// Get all values for a header (case-insensitive)
    /// Caller must free the returned slice with allocator.free()
    pub fn getAll(self: Headers, key: []const u8) ![]const []const u8 {
        const lower_key = try self.dupeLower(key);
        defer self.allocator.free(lower_key);

        if (self.map.get(lower_key)) |header| {
            const values = try self.allocator.alloc([]const u8, 1 + header.extra_values.items.len);
            values[0] = header.first_value;
            std.mem.copyForwards([]const u8, values[1..], header.extra_values.items);
            return values;
        }

        return &[0][]const u8{}; // Empty slice for non-existent header
    }

    /// Remove all values for a header (case-insensitive)
    pub fn remove(self: *Headers, key: []const u8) void {
        // Create lowercase key for lookup
        const lower_key = self.dupeLower(key) catch return;
        defer self.allocator.free(lower_key);

        if (self.map.fetchRemove(lower_key)) |kv| {
            // Create a mutable copy of the value to call deinit
            var value = kv.value;
            value.deinit(self.allocator);

            // Free the lowercase key used in the map
            self.allocator.free(kv.key);

            // Remove from list and free associated memory
            var i: usize = 0;
            while (i < self.list.items.len) {
                const entry = &self.list.items[i];
                if (std.ascii.eqlIgnoreCase(entry.key, key)) {
                    const removed = self.list.swapRemove(i);
                    self.allocator.free(removed.key);
                    if (!removed.is_first) {
                        // For non-first entries, we need to free the value
                        self.allocator.free(removed.value);
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Get an iterator over all headers
    pub fn iterator(self: Headers) HeaderIterator {
        return .{ .list = self.list.items };
    }

    /// Create a lowercase copy of a string
    fn dupeLower(self: Headers, s: []const u8) ![]const u8 {
        const lower = try self.allocator.alloc(u8, s.len);
        for (s, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }
        return lower;
    }

    /// Convert a string to lowercase (in-place, no allocation)
    fn toLowerInPlace(str: []u8) void {
        for (str) |*c| {
            c.* = std.ascii.toLower(c.*);
        }
    }

    pub const HeaderIterator = struct {
        list: []const HeaderEntry,
        index: usize = 0,

        pub fn next(self: *HeaderIterator) ?HeaderEntry {
            if (self.index >= self.list.len) return null;
            defer self.index += 1;
            return self.list[self.index];
        }
    };
};

// Tests
const testing = std.testing;

test "headers basic operations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = Headers.init(allocator);
    defer headers.deinit();

    // Test addBorrowed
    try headers.addBorrowed("Content-Type", "application/json");
    try headers.addBorrowed("X-Custom-Header", "value1");
    try headers.addBorrowed("x-custom-header", "value2"); // Same header, different case

    // Test get (case-insensitive)
    try testing.expectEqualStrings("application/json", headers.get("content-type").?);
    try testing.expectEqualStrings("value1", headers.get("X-Custom-Header").?);

    // Test getAll
    const values = try headers.getAll("x-custom-header");
    defer allocator.free(values);
    try testing.expectEqual(@as(usize, 2), values.len);
    try testing.expectEqualStrings("value1", values[0]);
    try testing.expectEqualStrings("value2", values[1]);

    // Test remove
    headers.remove("content-type");
    try testing.expect(headers.get("content-type") == null);
}

test "headers set replaces existing values" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.addBorrowed("X-Test", "value1");
    try headers.addBorrowed("X-Test", "value2");
    try headers.set("X-Test", "new-value");

    const values = try headers.getAll("x-test");
    defer allocator.free(values);
    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expectEqualStrings("new-value", values[0]);
}
