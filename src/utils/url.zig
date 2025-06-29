const std = @import("std");

/// URL utilities for H3Z
pub const UrlError = error{
    InvalidUrl,
    OutOfMemory,
    InvalidEncoding,
};

/// URL encode a string
pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (input) |char| {
        if (isUnreserved(char)) {
            try result.append(char);
        } else {
            try result.writer().print("%{X:0>2}", .{char});
        }
    }

    return result.toOwnedSlice();
}

/// URL decode a string
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex_str = input[i + 1 .. i + 3];
            const decoded_char = std.fmt.parseInt(u8, hex_str, 16) catch {
                return UrlError.InvalidEncoding;
            };
            try result.append(decoded_char);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(' ');
            i += 1;
        } else {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Check if character is unreserved (doesn't need encoding)
fn isUnreserved(char: u8) bool {
    return (char >= 'A' and char <= 'Z') or
        (char >= 'a' and char <= 'z') or
        (char >= '0' and char <= '9') or
        char == '-' or char == '.' or char == '_' or char == '~';
}

/// Parse query string into key-value pairs
pub fn parseQuery(allocator: std.mem.Allocator, query: []const u8) !std.StringHashMap([]const u8) {
    var params = std.StringHashMap([]const u8).init(allocator);

    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
            const key = param[0..eq_pos];
            const value = param[eq_pos + 1 ..];

            const decoded_key = try decode(allocator, key);
            const decoded_value = try decode(allocator, value);

            try params.put(decoded_key, decoded_value);
        } else {
            // Parameter without value
            const decoded_key = try decode(allocator, param);
            try params.put(decoded_key, "");
        }
    }

    return params;
}

/// Build query string from key-value pairs
pub fn buildQuery(allocator: std.mem.Allocator, params: std.StringHashMap([]const u8)) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var iter = params.iterator();
    var first = true;

    while (iter.next()) |entry| {
        if (!first) {
            try result.append('&');
        }
        first = false;

        const encoded_key = try encode(allocator, entry.key_ptr.*);
        defer allocator.free(encoded_key);

        const encoded_value = try encode(allocator, entry.value_ptr.*);
        defer allocator.free(encoded_value);

        try result.writer().print("{s}={s}", .{ encoded_key, encoded_value });
    }

    return result.toOwnedSlice();
}

/// Join URL paths
pub fn joinPath(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    if (parts.len == 0) return try allocator.dupe(u8, '/');

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (parts, 0..) |part, i| {
        if (part.len == 0) continue;

        // Add leading slash if not present and not first part
        if (i > 0 and !std.mem.startsWith(u8, part, '/')) {
            try result.append('/');
        }

        // Remove trailing slash except for root
        const clean_part = if (part.len > 1 and std.mem.endsWith(u8, part, '/'))
            part[0 .. part.len - 1]
        else
            part;

        try result.appendSlice(clean_part);
    }

    // Ensure result starts with /
    if (result.items.len == 0 or result.items[0] != '/') {
        try result.insert(0, '/');
    }

    return result.toOwnedSlice();
}

/// Normalize URL path (remove .. and . segments)
pub fn normalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var segments = std.ArrayList([]const u8).init(allocator);
    defer segments.deinit();

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) {
            continue; // Skip empty and current directory segments
        } else if (std.mem.eql(u8, segment, "..")) {
            if (segments.items.len > 0) {
                _ = segments.pop(); // Remove last segment
            }
        } else {
            try segments.append(segment);
        }
    }

    // Rebuild path
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.append('/');
    for (segments.items, 0..) |segment, i| {
        if (i > 0) try result.append('/');
        try result.appendSlice(segment);
    }

    return result.toOwnedSlice();
}

/// Extract file extension from URL path
pub fn getExtension(path: []const u8) ?[]const u8 {
    if (std.mem.lastIndexOf(u8, path, ".")) |dot_pos| {
        if (std.mem.lastIndexOf(u8, path, '/')) |slash_pos| {
            if (dot_pos > slash_pos) {
                return path[dot_pos..];
            }
        } else {
            return path[dot_pos..];
        }
    }
    return null;
}

/// Extract filename from URL path
pub fn getFilename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOf(u8, path, '/')) |slash_pos| {
        return path[slash_pos + 1 ..];
    }
    return path;
}

/// Check if path is safe (doesn't contain .. or other dangerous patterns)
pub fn isSafePath(path: []const u8) bool {
    // Check for dangerous patterns
    if (std.mem.indexOf(u8, path, "..") != null) return false;
    if (std.mem.indexOf(u8, path, "//") != null) return false;
    if (std.mem.startsWith(u8, path, "/..")) return false;
    if (std.mem.endsWith(u8, path, "/..")) return false;

    // Check for null bytes
    if (std.mem.indexOf(u8, path, "\x00") != null) return false;

    return true;
}

/// Build absolute URL from base URL and relative path
pub fn resolve(allocator: std.mem.Allocator, base_url: []const u8, relative_path: []const u8) ![]u8 {
    const base_uri = try std.Uri.parse(base_url);

    if (std.mem.startsWith(u8, relative_path, "http://") or
        std.mem.startsWith(u8, relative_path, "https://"))
    {
        // Absolute URL
        return try allocator.dupe(u8, relative_path);
    }

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    // Scheme and authority
    try result.writer().print("{s}://", .{base_uri.scheme});
    if (base_uri.host) |host| {
        try result.appendSlice(host.raw);
        if (base_uri.port) |port| {
            try result.writer().print(":{d}", .{port});
        }
    }

    // Path
    if (std.mem.startsWith(u8, relative_path, '/')) {
        // Absolute path
        try result.appendSlice(relative_path);
    } else {
        // Relative path
        const base_path = base_uri.path;
        const dir_path = if (std.mem.lastIndexOf(u8, base_path, '/')) |last_slash|
            base_path[0 .. last_slash + 1]
        else
            '/';

        const full_path = try joinPath(allocator, &.{ dir_path, relative_path });
        defer allocator.free(full_path);

        const normalized = try normalizePath(allocator, full_path);
        defer allocator.free(normalized);

        try result.appendSlice(normalized);
    }

    return result.toOwnedSlice();
}

test "url utilities" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test encoding/decoding
    const original = "hello world!";
    const encoded = try encode(allocator, original);
    defer allocator.free(encoded);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);

    try testing.expectEqualStrings(original, decoded);

    // Test query parsing
    const query = "name=John%20Doe&age=30&city=New%20York";
    var params = try parseQuery(allocator, query);
    defer {
        var iter = params.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        params.deinit();
    }

    try testing.expectEqualStrings("John Doe", params.get("name").?);
    try testing.expectEqualStrings("30", params.get("age").?);

    // Test path normalization
    const path = "/api/../users/./123";
    const normalized = try normalizePath(allocator, path);
    defer allocator.free(normalized);

    try testing.expectEqualStrings("/users/123", normalized);

    // Test path safety
    try testing.expect(isSafePath("/safe/path"));
    try testing.expect(!isSafePath("/unsafe/../path"));
    try testing.expect(!isSafePath("/path/with/nullbyte\x00"));
}
