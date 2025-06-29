const std = @import("std");
const StatusCode = @import("status.zig").StatusCode;
const Headers = @import("request.zig").Headers;

/// HTTP response builder
pub const Response = struct {
    status: StatusCode,
    headers: Headers,
    body: ?[]const u8,
    allocator: std.mem.Allocator,
    _body_owned: bool, // Track if we own the body memory

    /// Initialize a new response
    pub fn init(allocator: std.mem.Allocator) Response {
        return Response{
            .status = .ok,
            .headers = Headers.init(allocator),
            .body = null,
            .allocator = allocator,
            ._body_owned = false,
        };
    }

    /// Clean up response resources
    pub fn deinit(self: *Response) void {
        // Free headers
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();

        // Free body if we own it
        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }
    }

    /// Set response status code
    pub fn setStatus(self: *Response, status: StatusCode) *Response {
        self.status = status;
        return self;
    }

    /// Set a response header
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !*Response {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        // If header already exists, free the old value
        if (self.headers.get(name_copy)) |old_value| {
            self.allocator.free(old_value);
        }

        try self.headers.put(name_copy, value_copy);
        return self;
    }

    /// Remove a response header
    pub fn removeHeader(self: *Response, name: []const u8) *Response {
        if (self.headers.fetchRemove(name)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
        return self;
    }

    /// Get a response header value
    pub fn getHeader(self: *const Response, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    /// Set response body as text
    pub fn text(self: *Response, content: []const u8) !*Response {
        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }

        self.body = try self.allocator.dupe(u8, content);
        self._body_owned = true;

        _ = try self.setHeader("Content-Type", "text/plain; charset=utf-8");
        try self.setContentLength();

        return self;
    }

    /// Set response body as HTML
    pub fn html(self: *Response, content: []const u8) !*Response {
        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }

        self.body = try self.allocator.dupe(u8, content);
        self._body_owned = true;

        try self.setHeader("Content-Type", "text/html; charset=utf-8");
        try self.setContentLength();

        return self;
    }

    /// Set response body as JSON
    pub fn json(self: *Response, data: anytype) !*Response {
        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }

        const json_str = try std.json.stringifyAlloc(self.allocator, data, .{});
        self.body = json_str;
        self._body_owned = true;

        _ = try self.setHeader("Content-Type", "application/json; charset=utf-8");
        try self.setContentLength();

        return self;
    }

    /// Set response body as raw bytes
    pub fn bytes(self: *Response, content: []const u8, content_type: ?[]const u8) !*Response {
        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }

        self.body = try self.allocator.dupe(u8, content);
        self._body_owned = true;

        if (content_type) |ct| {
            try self.setHeader("Content-Type", ct);
        } else {
            try self.setHeader("Content-Type", "application/octet-stream");
        }

        try self.setContentLength();

        return self;
    }

    /// Set response body from file
    pub fn file(self: *Response, file_path: []const u8) !*Response {
        const file_content = try std.fs.cwd().readFileAlloc(self.allocator, file_path, std.math.maxInt(usize));

        if (self._body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }

        self.body = file_content;
        self._body_owned = true;

        // Guess content type from file extension
        const content_type = guessContentType(file_path);
        _ = try self.setHeader("Content-Type", content_type);
        try self.setContentLength();

        return self;
    }

    /// Redirect to another URL
    pub fn redirect(self: *Response, url: []const u8, status: ?StatusCode) !*Response {
        self.status = status orelse .found;
        try self.setHeader("Location", url);

        if (self.body == null) {
            const redirect_body = try std.fmt.allocPrint(self.allocator, "<!DOCTYPE html><html><head><title>Redirecting</title></head>" ++
                "<body><p>Redirecting to <a href=\"{s}\">{s}</a></p></body></html>", .{ url, url });

            self.body = redirect_body;
            self._body_owned = true;
            try self.setHeader("Content-Type", "text/html; charset=utf-8");
            try self.setContentLength();
        }

        return self;
    }

    /// Set cookie
    pub fn setCookie(self: *Response, name: []const u8, value: []const u8, options: CookieOptions) !*Response {
        var cookie_str = std.ArrayList(u8).init(self.allocator);
        defer cookie_str.deinit();

        try cookie_str.writer().print("{s}={s}", .{ name, value });

        if (options.max_age) |max_age| {
            try cookie_str.writer().print("; Max-Age={d}", .{max_age});
        }

        if (options.domain) |domain| {
            try cookie_str.writer().print("; Domain={s}", .{domain});
        }

        if (options.path) |path| {
            try cookie_str.writer().print("; Path={s}", .{path});
        }

        if (options.secure) {
            try cookie_str.writer().writeAll("; Secure");
        }

        if (options.http_only) {
            try cookie_str.writer().writeAll("; HttpOnly");
        }

        if (options.same_site) |same_site| {
            try cookie_str.writer().print("; SameSite={s}", .{switch (same_site) {
                .strict => "Strict",
                .lax => "Lax",
                .none => "None",
            }});
        }

        try self.setHeader("Set-Cookie", cookie_str.items);
        return self;
    }

    /// Clear cookie
    pub fn clearCookie(self: *Response, name: []const u8, options: CookieOptions) !*Response {
        var clear_options = options;
        clear_options.max_age = 0;
        return self.setCookie(name, "", clear_options);
    }

    /// Set Content-Length header based on body size
    fn setContentLength(self: *Response) !void {
        if (self.body) |body| {
            const length_str = try std.fmt.allocPrint(self.allocator, "{d}", .{body.len});
            _ = try self.setHeader("Content-Length", length_str);
        }
    }

    /// Write response to stream
    pub fn writeTo(self: *const Response, writer: anytype) !void {
        // Status line
        try writer.print("HTTP/1.1 {d} {s}\r\n", .{
            @intFromEnum(self.status),
            self.status.phrase(),
        });

        // Headers
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            try writer.print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Empty line
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |body| {
            try writer.writeAll(body);
        }
    }

    /// Get response as bytes (for testing)
    pub fn toBytes(self: *const Response) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try self.writeTo(buffer.writer());
        return try self.allocator.dupe(u8, buffer.items);
    }
};

/// Cookie options
pub const CookieOptions = struct {
    max_age: ?i64 = null,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,

    pub const SameSite = enum {
        strict,
        lax,
        none,
    };
};

/// Guess content type from file extension
fn guessContentType(file_path: []const u8) []const u8 {
    const ext = std.fs.path.extension(file_path);

    if (std.mem.eql(u8, ext, ".html") or std.mem.eql(u8, ext, ".htm")) {
        return "text/html; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".css")) {
        return "text/css; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".js")) {
        return "application/javascript; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".json")) {
        return "application/json; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".png")) {
        return "image/png";
    } else if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) {
        return "image/jpeg";
    } else if (std.mem.eql(u8, ext, ".gif")) {
        return "image/gif";
    } else if (std.mem.eql(u8, ext, ".svg")) {
        return "image/svg+xml";
    } else if (std.mem.eql(u8, ext, ".txt")) {
        return "text/plain; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".xml")) {
        return "application/xml; charset=utf-8";
    } else if (std.mem.eql(u8, ext, ".pdf")) {
        return "application/pdf";
    } else {
        return "application/octet-stream";
    }
}

test "response builder" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var response = Response.init(allocator);
    defer response.deinit();

    _ = try response.setStatus(.created)
        .setHeader("X-Custom", "test")
        .json(.{ .message = "success", .id = 123 });

    try testing.expect(response.status == .created);
    try testing.expectEqualStrings("test", response.getHeader("X-Custom").?);
    try testing.expect(response.body != null);
    try testing.expect(std.mem.indexOf(u8, response.body.?, "success") != null);
}

test "content type guessing" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", guessContentType("index.html"));
    try std.testing.expectEqualStrings("application/javascript; charset=utf-8", guessContentType("app.js"));
    try std.testing.expectEqualStrings("image/png", guessContentType("logo.png"));
    try std.testing.expectEqualStrings("application/octet-stream", guessContentType("unknown.xyz"));
}
