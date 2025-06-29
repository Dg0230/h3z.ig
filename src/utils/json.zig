const std = @import("std");

/// JSON utilities for H3Z
pub const JsonError = error{
    InvalidJson,
    OutOfMemory,
    InvalidType,
};

/// Parse JSON string to a specific type
pub fn parse(comptime T: type, allocator: std.mem.Allocator, json_str: []const u8) !T {
    const parsed = try std.json.parseFromSlice(T, allocator, json_str, .{});
    return parsed.value;
}

/// Stringify a value to JSON
pub fn stringify(value: anytype, allocator: std.mem.Allocator) ![]u8 {
    return std.json.stringifyAlloc(allocator, value, .{});
}

/// Stringify with custom options
pub fn stringifyWithOptions(value: anytype, allocator: std.mem.Allocator, options: std.json.StringifyOptions) ![]u8 {
    return std.json.stringifyAlloc(allocator, value, options);
}

/// Pretty print JSON with indentation
pub fn prettyStringify(value: anytype, allocator: std.mem.Allocator) ![]u8 {
    return std.json.stringifyAlloc(allocator, value, .{
        .whitespace = .indent_2,
    });
}

/// Validate JSON string
pub fn validate(json_str: []const u8) bool {
    var stream = std.json.Scanner.init(json_str);
    while (true) {
        const token = stream.next() catch return false;
        if (token == .end_of_document) break;
    }
    return true;
}

/// Extract value from JSON object by key path
pub fn extract(comptime T: type, json_value: std.json.Value, path: []const []const u8) ?T {
    var current = json_value;

    for (path) |key| {
        switch (current) {
            .object => |obj| {
                current = obj.get(key) orelse return null;
            },
            else => return null,
        }
    }

    return switch (T) {
        []const u8 => switch (current) {
            .string => |s| s,
            else => null,
        },
        i64 => switch (current) {
            .integer => |i| i,
            else => null,
        },
        f64 => switch (current) {
            .float => |f| f,
            .integer => |i| @floatFromInt(i),
            else => null,
        },
        bool => switch (current) {
            .bool => |b| b,
            else => null,
        },
        else => null,
    };
}

/// Merge two JSON objects
pub fn merge(allocator: std.mem.Allocator, base: std.json.Value, other: std.json.Value) !std.json.Value {
    if (base != .object or other != .object) {
        return other; // Non-objects can't be merged
    }

    var result = std.json.ObjectMap.init(allocator);

    // Copy base object
    var base_iter = base.object.iterator();
    while (base_iter.next()) |entry| {
        try result.put(entry.key_ptr.*, entry.value_ptr.*);
    }

    // Merge other object
    var other_iter = other.object.iterator();
    while (other_iter.next()) |entry| {
        if (result.get(entry.key_ptr.*)) |existing| {
            // Recursively merge objects
            if (existing == .object and entry.value_ptr.* == .object) {
                const merged = try merge(allocator, existing, entry.value_ptr.*);
                try result.put(entry.key_ptr.*, merged);
            } else {
                try result.put(entry.key_ptr.*, entry.value_ptr.*);
            }
        } else {
            try result.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    return std.json.Value{ .object = result };
}

/// Create JSON response with common structure
pub fn createResponse(allocator: std.mem.Allocator, success: bool, message: ?[]const u8, data: anytype) ![]u8 {
    const Response = struct {
        success: bool,
        message: ?[]const u8 = null,
        data: @TypeOf(data),
        timestamp: i64,
    };

    const response = Response{
        .success = success,
        .message = message,
        .data = data,
        .timestamp = std.time.timestamp(),
    };

    return stringify(response, allocator);
}

/// Create error JSON response
pub fn createErrorResponse(allocator: std.mem.Allocator, message: []const u8, code: ?i32) ![]u8 {
    const ErrorResponse = struct {
        success: bool = false,
        @"error": struct {
            message: []const u8,
            code: ?i32 = null,
        },
        timestamp: i64,
    };

    const response = ErrorResponse{
        .@"error" = .{
            .message = message,
            .code = code,
        },
        .timestamp = std.time.timestamp(),
    };

    return stringify(response, allocator);
}

test "json utilities" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test parse
    const TestData = struct { name: []const u8, age: i32 };
    const json_str = "{\"name\":\"John\",\"age\":30}";
    const parsed = try parse(TestData, allocator, json_str);
    defer allocator.free(parsed.name);

    try testing.expectEqualStrings("John", parsed.name);
    try testing.expect(parsed.age == 30);

    // Test stringify
    const data = TestData{ .name = "Jane", .age = 25 };
    const json_result = try stringify(data, allocator);
    defer allocator.free(json_result);

    try testing.expect(std.mem.indexOf(u8, json_result, "Jane") != null);
    try testing.expect(std.mem.indexOf(u8, json_result, "25") != null);

    // Test validation
    try testing.expect(validate("{\"valid\":true}"));
    try testing.expect(!validate("{invalid"));
}
