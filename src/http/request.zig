const std = @import("std");
const headers = @import("headers.zig");

/// HTTP methods
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,

    /// Parse HTTP method from string
    pub fn parse(method_str: []const u8) ?HttpMethod {
        if (std.mem.eql(u8, method_str, "GET")) return .GET;
        if (std.mem.eql(u8, method_str, "POST")) return .POST;
        if (std.mem.eql(u8, method_str, "PUT")) return .PUT;
        if (std.mem.eql(u8, method_str, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, method_str, "PATCH")) return .PATCH;
        if (std.mem.eql(u8, method_str, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, method_str, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, method_str, "TRACE")) return .TRACE;
        if (std.mem.eql(u8, method_str, "CONNECT")) return .CONNECT;
        return null;
    }

    /// Convert method to string
    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .PATCH => "PATCH",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
        };
    }
};

/// HTTP version
pub const HttpVersion = enum {
    @"1.0",
    @"1.1",
    @"2.0",
    @"3.0",

    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .@"1.0" => "HTTP/1.0",
            .@"1.1" => "HTTP/1.1",
            .@"2.0" => "HTTP/2.0",
            .@"3.0" => "HTTP/3.0",
        };
    }
};

/// HTTP headers map
pub const Headers = std.StringHashMap([]const u8);

/// HTTP request representation
pub const Request = struct {
    method: HttpMethod,
    uri: std.Uri,
    version: HttpVersion,
    headers: headers.Headers,
    body: ?[]const u8,
    allocator: std.mem.Allocator,
    _allocated_uri: ?[]const u8 = null, // Store the allocated URI string if any

    /// Initialize a new request
    pub fn init(allocator: std.mem.Allocator) Request {
        return Request{
            .method = .GET,
            .uri = std.Uri{
                .scheme = "",
                .user = null,
                .password = null,
                .host = null,
                .port = null,
                .path = .{ .raw = "/" },
                .query = null,
                .fragment = null,
            },
            .version = .@"1.1",
            .headers = headers.Headers.init(allocator),
            .body = null,
            .allocator = allocator,
        };
    }

    /// Clean up request resources
    pub fn deinit(self: *Request) void {
        self.headers.deinit();
        if (self.body) |body| {
            self.allocator.free(body);
        }
        if (self._allocated_uri) |uri| {
            self.allocator.free(uri);
        }
    }

    /// Remove a header (case-insensitive)
    pub fn removeHeader(self: *Request, name: []const u8) void {
        self.headers.remove(name);
    }

    /// Set a header (replaces any existing values)
    pub fn setHeader(self: *Request, name: []const u8, value: []const u8) !void {
        try self.headers.set(name, value);
    }

    /// Add a header (appends to existing values)
    pub fn addHeader(self: *Request, name: []const u8, value: []const u8) !void {
        try self.headers.addBorrowed(name, value);
    }

    /// Get header value by name (case-insensitive)
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    /// Get all header values by name (case-insensitive)
    /// Caller must free the returned slice with allocator.free()
    pub fn getAllHeaders(self: *const Request, name: []const u8) ![]const []const u8 {
        return self.headers.getAll(name);
    }

    /// Get Content-Type header
    pub fn contentType(self: *const Request) ?[]const u8 {
        return self.header("content-type");
    }

    /// Get Content-Length header as integer
    pub fn contentLength(self: *const Request) ?u64 {
        const length_str = self.header("content-length") orelse return null;
        return std.fmt.parseInt(u64, length_str, 10) catch null;
    }

    /// Get User-Agent header
    pub fn userAgent(self: *const Request) ?[]const u8 {
        return self.header("user-agent");
    }

    /// Get Authorization header
    pub fn authorization(self: *const Request) ?[]const u8 {
        return self.header("authorization");
    }

    /// Check if request expects JSON response
    pub fn acceptsJson(self: *const Request) bool {
        const accept = self.header("accept") orelse return false;
        return std.mem.indexOf(u8, accept, "application/json") != null;
    }

    /// Check if request body is JSON
    pub fn isJson(self: *const Request) bool {
        const content_type = self.contentType() orelse return false;
        return std.mem.startsWith(u8, content_type, "application/json");
    }

    /// Check if request body is form data
    pub fn isForm(self: *const Request) bool {
        const content_type = self.contentType() orelse return false;
        return std.mem.startsWith(u8, content_type, "application/x-www-form-urlencoded");
    }

    /// Check if request body is multipart form data
    pub fn isMultipart(self: *const Request) bool {
        const content_type = self.contentType() orelse return false;
        return std.mem.startsWith(u8, content_type, "multipart/form-data");
    }

    /// Parse query parameters from URI
    pub fn queryParams(self: *const Request, allocator: std.mem.Allocator) !std.StringHashMap([]const u8) {
        var params = std.StringHashMap([]const u8).init(allocator);

        const query = self.uri.query orelse return params;

        var iter = std.mem.splitScalar(u8, query, '&');
        while (iter.next()) |param| {
            if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                const key = param[0..eq_pos];
                const value = param[eq_pos + 1 ..];

                // URL decode key and value
                const decoded_key = try std.Uri.unescapeString(allocator, key);
                const decoded_value = try std.Uri.unescapeString(allocator, value);

                try params.put(decoded_key, decoded_value);
            } else {
                // Parameter without value
                const decoded_key = try std.Uri.unescapeString(allocator, param);
                try params.put(decoded_key, "");
            }
        }

        return params;
    }

    /// Get single query parameter value
    pub fn queryParam(self: *const Request, allocator: std.mem.Allocator, name: []const u8) !?[]const u8 {
        const params = try self.queryParams(allocator);
        defer {
            var iter = params.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            params.deinit();
        }

        if (params.get(name)) |value| {
            return try allocator.dupe(u8, value);
        }

        return null;
    }

    /// Parse JSON body
    pub fn json(self: *const Request, comptime T: type, allocator: std.mem.Allocator) !T {
        const body = self.body orelse return error.NoBody;

        if (!self.isJson()) {
            return error.NotJson;
        }

        const parsed = try std.json.parseFromSlice(T, allocator, body, .{});
        return parsed.value;
    }

    /// Get request body as string
    pub fn text(self: *const Request) ?[]const u8 {
        return self.body;
    }
};

/// Parse error types
pub const ParseError = error{
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    InvalidHeader,
    MalformedRequest,
    OutOfMemory,
};

/// Parse HTTP request from raw bytes
pub fn parseRequest(allocator: std.mem.Allocator, data: []const u8) ParseError!Request {
    var request = Request.init(allocator);
    errdefer request.deinit();

    // Find end of headers (double CRLF)
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse
        std.mem.indexOf(u8, data, "\n\n") orelse
        return ParseError.MalformedRequest;

    const headers_section = data[0..header_end];
    const body_start = header_end + (if (std.mem.indexOf(u8, data, "\r\n\r\n") != null) @as(usize, 4) else @as(usize, 2));

    // Parse request line and headers
    var lines = std.mem.splitScalar(u8, headers_section, '\n');

    // Parse request line (first line)
    const request_line = lines.next() orelse return ParseError.MalformedRequest;
    const trimmed_line = std.mem.trim(u8, request_line, " \r\n");

    var parts = std.mem.splitScalar(u8, trimmed_line, ' ');

    // Method
    const method_str = parts.next() orelse return ParseError.MalformedRequest;
    request.method = HttpMethod.parse(method_str) orelse return ParseError.InvalidMethod;

    // URI
    const uri_str = parts.next() orelse return ParseError.MalformedRequest;
    // Create a full URI from the relative path by prepending http://localhost
    const full_uri = if (std.mem.startsWith(u8, uri_str, "http://") or std.mem.startsWith(u8, uri_str, "https://"))
        uri_str
    else
        try std.fmt.allocPrint(allocator, "http://localhost{s}", .{uri_str});

    // Store the allocated URI string if we created one
    if (full_uri.ptr != uri_str.ptr) {
        request._allocated_uri = full_uri;
    }

    request.uri = std.Uri.parse(full_uri) catch |err| {
        // If we allocated memory for full_uri, free it
        if (!std.mem.startsWith(u8, uri_str, "http://") and !std.mem.startsWith(u8, uri_str, "https://")) {
            allocator.free(full_uri);
        }
        std.log.err("Failed to parse URI: {s} - Error: {}", .{ uri_str, err });
        return ParseError.InvalidUri;
    };

    // Note: If we allocated memory for full_uri and it's not the original uri_str,
    // we have a small memory leak here. In a production system, we'd need to
    // track allocated URIs and clean them up when the request is destroyed.

    // Version
    const version_str = parts.next() orelse return ParseError.MalformedRequest;
    const trimmed_version = std.mem.trim(u8, version_str, " \r\n\t");

    // Debug version parsing
    // std.log.info("Parsing version: '{s}' (length: {})", .{ trimmed_version, trimmed_version.len });

    if (std.mem.eql(u8, trimmed_version, "HTTP/1.0")) {
        request.version = .@"1.0";
    } else if (std.mem.eql(u8, trimmed_version, "HTTP/1.1")) {
        request.version = .@"1.1";
    } else if (std.mem.eql(u8, trimmed_version, "HTTP/2.0")) {
        request.version = .@"2.0";
    } else if (std.mem.eql(u8, trimmed_version, "HTTP/3.0")) {
        request.version = .@"3.0";
    } else {
        // std.log.err("Unknown HTTP version: '{s}'", .{trimmed_version});
        return ParseError.InvalidVersion;
    }

    // Parse headers
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\n");
        if (trimmed.len == 0) continue;

        const colon_pos = std.mem.indexOf(u8, trimmed, ":") orelse return ParseError.InvalidHeader;
        const name = std.mem.trim(u8, trimmed[0..colon_pos], " ");
        const value = std.mem.trim(u8, trimmed[colon_pos + 1 ..], " ");

        try request.headers.set(name, value);
    }

    // Handle body
    if (body_start < data.len) {
        const body_data = data[body_start..];
        if (body_data.len > 0) {
            request.body = try allocator.dupe(u8, body_data);
        }
    }

    return request;
}

test "http method parsing" {
    const testing = std.testing;

    try testing.expect(HttpMethod.parse("GET") == .GET);
    try testing.expect(HttpMethod.parse("POST") == .POST);
    try testing.expect(HttpMethod.parse("invalid") == null);

    try testing.expectEqualStrings("GET", HttpMethod.GET.toString());
    try testing.expectEqualStrings("POST", HttpMethod.POST.toString());
}

test "request header access" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request = Request.init(allocator);
    defer request.deinit();

    // Test setting and getting headers
    try request.setHeader("Content-Type", "application/json");
    try testing.expectEqualStrings("application/json", request.header("content-type").?);
    try testing.expectEqualStrings("application/json", request.header("Content-Type").?);

    // Test multiple values for same header
    try request.addHeader("X-Test", "value1");
    try request.addHeader("x-test", "value2");

    // Should return the first value
    try testing.expectEqualStrings("value1", request.header("X-Test").?);

    // Test getting all values
    const values = try request.getAllHeaders("x-test");
    defer allocator.free(values);
    try testing.expectEqual(@as(usize, 2), values.len);
    try testing.expectEqualStrings("value1", values[0]);
    try testing.expectEqualStrings("value2", values[1]);

    // Test removing header
    request.removeHeader("content-type");
    try testing.expect(request.header("content-type") == null);

    // Test non-existent header
    try testing.expect(request.header("non-existent") == null);
}

test "request parsing" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const raw_request = "GET /api/users?page=1 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Type: application/json\r\n" ++
        "\r\n" ++
        "{\"name\":\"test\"}";

    var request = try parseRequest(allocator, raw_request);
    defer request.deinit();

    try testing.expect(request.method == .GET);
    const path_str = switch (request.uri.path) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    };
    try testing.expectEqualStrings("/api/users", path_str);
    try testing.expect(request.version == .@"1.1");
    try testing.expectEqualStrings("example.com", request.header("Host").?);
    try testing.expectEqualStrings("{\"name\":\"test\"}", request.body.?);
}
