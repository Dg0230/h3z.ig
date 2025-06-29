const std = @import("std");
const Request = @import("http/request.zig").Request;
const Response = @import("http/response.zig").Response;

/// Route parameters map
pub const RouteParams = std.StringHashMap([]const u8);

/// Locals storage for middleware communication
pub const Locals = std.StringHashMap([]const u8);

/// HTTP request context containing request, response, and metadata
pub const Context = struct {
    request: Request,
    response: Response,
    params: RouteParams,
    locals: Locals,
    allocator: std.mem.Allocator,

    // Internal state
    _aborted: bool = false,
    _start_time: i64,

    /// Initialize a new context
    pub fn init(allocator: std.mem.Allocator, request: Request) Context {
        return Context{
            .request = request,
            .response = Response.init(allocator),
            .params = RouteParams.init(allocator),
            .locals = Locals.init(allocator),
            .allocator = allocator,
            ._start_time = std.time.milliTimestamp(),
        };
    }

    /// Clean up context resources
    pub fn deinit(self: *Context) void {
        self.response.deinit();

        // Free route params
        var params_iter = self.params.iterator();
        while (params_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.params.deinit();

        // Free locals
        var locals_iter = self.locals.iterator();
        while (locals_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.locals.deinit();
    }

    /// Get route parameter value
    pub fn param(self: *const Context, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    /// Set route parameter (used internally by router)
    pub fn setParam(self: *Context, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.params.put(name_copy, value_copy);
    }

    /// Get local value (for middleware communication)
    pub fn local(self: *const Context, name: []const u8) ?[]const u8 {
        return self.locals.get(name);
    }

    /// Set local value (for middleware communication)
    pub fn setLocal(self: *Context, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.locals.put(name_copy, value_copy);
    }

    /// Get query parameter value
    pub fn query(self: *const Context, name: []const u8) !?[]const u8 {
        return self.request.queryParam(self.allocator, name);
    }

    /// Get all query parameters
    pub fn queryAll(self: *const Context) !RouteParams {
        return self.request.queryParams(self.allocator);
    }

    /// Get request header value
    pub fn header(self: *const Context, name: []const u8) ?[]const u8 {
        return self.request.header(name);
    }

    /// Set response header
    pub fn setHeader(self: *Context, name: []const u8, value: []const u8) !void {
        _ = try self.response.setHeader(name, value);
    }

    /// Set response status
    pub fn status(self: *Context, code: @import("http/status.zig").StatusCode) void {
        _ = self.response.setStatus(code);
    }

    /// Send text response
    pub fn text(self: *Context, content: []const u8) !void {
        _ = try self.response.text(content);
    }

    /// Send HTML response
    pub fn html(self: *Context, content: []const u8) !void {
        _ = try self.response.html(content);
    }

    /// Send JSON response
    pub fn json(self: *Context, data: anytype) !void {
        _ = try self.response.json(data);
    }

    /// Send file response
    pub fn file(self: *Context, file_path: []const u8) !void {
        _ = try self.response.file(file_path);
    }

    /// Redirect to URL
    pub fn redirect(self: *Context, redirect_url: []const u8, status_code: ?@import("http/status.zig").StatusCode) !void {
        _ = try self.response.redirect(redirect_url, status_code);
    }

    /// Set cookie
    pub fn setCookie(self: *Context, name: []const u8, value: []const u8, options: @import("http/response.zig").CookieOptions) !void {
        _ = try self.response.setCookie(name, value, options);
    }

    /// Clear cookie
    pub fn clearCookie(self: *Context, name: []const u8, options: @import("http/response.zig").CookieOptions) !void {
        _ = try self.response.clearCookie(name, options);
    }

    /// Parse request body as JSON
    pub fn bodyJson(self: *const Context, comptime T: type) !T {
        return self.request.json(T, self.allocator);
    }

    /// Get request body as text
    pub fn bodyText(self: *const Context) ?[]const u8 {
        return self.request.text();
    }

    /// Parse form data from request body
    pub fn bodyForm(self: *const Context) !std.StringHashMap([]const u8) {
        const body = self.request.body orelse return error.NoBody;

        if (!self.request.isForm()) {
            return error.NotForm;
        }

        var form_data = std.StringHashMap([]const u8).init(self.allocator);

        var iter = std.mem.splitScalar(u8, body, '&');
        while (iter.next()) |form_param| {
            if (std.mem.indexOf(u8, form_param, "=")) |eq_pos| {
                const key = form_param[0..eq_pos];
                const value = form_param[eq_pos + 1 ..];

                // URL decode key and value
                const decoded_key = try std.Uri.unescapeString(self.allocator, key);
                const decoded_value = try std.Uri.unescapeString(self.allocator, value);

                try form_data.put(decoded_key, decoded_value);
            }
        }

        return form_data;
    }

    /// Check if request accepts a specific content type
    pub fn accepts(self: *const Context, content_type: []const u8) bool {
        const accept_header = self.request.header("accept") orelse return false;
        return std.mem.indexOf(u8, accept_header, content_type) != null;
    }

    /// Check if request is secure (HTTPS)
    pub fn isSecure(self: *const Context) bool {
        // Check for X-Forwarded-Proto header (common with reverse proxies)
        if (self.request.header("x-forwarded-proto")) |proto| {
            return std.mem.eql(u8, proto, "https");
        }

        // Check for X-Forwarded-SSL header
        if (self.request.header("x-forwarded-ssl")) |ssl| {
            return std.mem.eql(u8, ssl, "on");
        }

        // TODO: In a real implementation, this would check the actual connection type
        return false;
    }

    /// Get client IP address
    pub fn ip(self: *const Context) ?[]const u8 {
        // Check common forwarded headers first
        if (self.request.header("x-forwarded-for")) |xff| {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if (std.mem.indexOf(u8, xff, ",")) |comma_pos| {
                return std.mem.trim(u8, xff[0..comma_pos], " ");
            }
            return xff;
        }

        if (self.request.header("x-real-ip")) |real_ip| {
            return real_ip;
        }

        // TODO: In a real implementation, this would get the actual remote address
        return null;
    }

    /// Get user agent string
    pub fn userAgent(self: *const Context) ?[]const u8 {
        return self.request.userAgent();
    }

    /// Abort the request (prevents further middleware execution)
    pub fn abort(self: *Context) void {
        self._aborted = true;
    }

    /// Check if request has been aborted
    pub fn isAborted(self: *const Context) bool {
        return self._aborted;
    }

    /// Get request processing time in milliseconds
    pub fn processingTime(self: *const Context) i64 {
        return std.time.milliTimestamp() - self._start_time;
    }

    /// Get request method
    pub fn method(self: *const Context) @import("http/request.zig").HttpMethod {
        return self.request.method;
    }

    /// Get request path
    pub fn path(self: *const Context) []const u8 {
        switch (self.request.uri.path) {
            .raw => |raw| return raw,
            .percent_encoded => |encoded| return encoded,
        }
    }

    /// Get request URL (path + query)
    pub fn url(self: *const Context) []const u8 {
        // TODO: Implement proper URL reconstruction
        return self.request.uri.path;
    }

    /// Check if request method matches
    pub fn isMethod(self: *const Context, check_method: @import("http/request.zig").HttpMethod) bool {
        return self.request.method == check_method;
    }

    /// Check if request path matches pattern
    pub fn isPath(self: *const Context, pattern: []const u8) bool {
        return std.mem.eql(u8, self.request.uri.path, pattern);
    }

    /// Check if this is a GET request
    pub fn isGet(self: *const Context) bool {
        return self.request.method == .GET;
    }

    /// Check if this is a POST request
    pub fn isPost(self: *const Context) bool {
        return self.request.method == .POST;
    }

    /// Check if this is a PUT request
    pub fn isPut(self: *const Context) bool {
        return self.request.method == .PUT;
    }

    /// Check if this is a DELETE request
    pub fn isDelete(self: *const Context) bool {
        return self.request.method == .DELETE;
    }

    /// Check if this is a PATCH request
    pub fn isPatch(self: *const Context) bool {
        return self.request.method == .PATCH;
    }

    /// Check if request expects JSON response
    pub fn expectsJson(self: *const Context) bool {
        return self.request.acceptsJson();
    }

    /// Check if request body is JSON
    pub fn hasJsonBody(self: *const Context) bool {
        return self.request.isJson();
    }

    /// Log request information
    pub fn log(self: *const Context, comptime level: std.log.Level, comptime format: []const u8, args: anytype) void {
        const method_str = self.request.method.toString();
        const path_str = self.request.uri.path;
        const processing_time = self.processingTime();

        std.log.scoped(.h3z).log(level, "[{s} {s}] " ++ format ++ " ({d}ms)", .{ method_str, path_str } ++ args ++ .{processing_time});
    }
};

test "context operations" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request = Request.init(allocator);
    defer request.deinit();

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    // Test params
    try ctx.setParam("id", "123");
    try testing.expectEqualStrings("123", ctx.param("id").?);

    // Test locals
    try ctx.setLocal("user", "john");
    try testing.expectEqualStrings("john", ctx.local("user").?);

    // Test convenience methods
    try testing.expect(ctx.isGet());
    try testing.expect(!ctx.isPost());
}
