const std = @import("std");
const Context = @import("context.zig").Context;
const Middleware = @import("middleware.zig").Middleware;
const HttpMethod = @import("http/request.zig").HttpMethod;

/// Route handler function type
pub const Handler = *const fn (ctx: *Context) anyerror!void;

/// Route parameters extracted from URL patterns
pub const RouteParams = std.StringHashMap([]const u8);

/// Route pattern matcher
pub const RouteMatcher = struct {
    pattern: []const u8,
    method: ?HttpMethod = null,
    is_wildcard: bool = false,
    param_names: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    /// Initialize a route matcher
    pub fn init(allocator: std.mem.Allocator, pattern: []const u8, method: ?HttpMethod) !RouteMatcher {
        var matcher = RouteMatcher{
            .pattern = try allocator.dupe(u8, pattern),
            .method = method,
            .param_names = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };

        // Check if this is a wildcard route
        matcher.is_wildcard = std.mem.endsWith(u8, pattern, "*");

        // Extract parameter names from pattern
        try matcher.extractParamNames();

        return matcher;
    }

    /// Clean up matcher resources
    pub fn deinit(self: *RouteMatcher) void {
        self.allocator.free(self.pattern);
        for (self.param_names.items) |name| {
            self.allocator.free(name);
        }
        self.param_names.deinit();
    }

    /// Extract parameter names from route pattern
    fn extractParamNames(self: *RouteMatcher) !void {
        var iter = std.mem.splitScalar(u8, self.pattern, '/');
        while (iter.next()) |segment| {
            if (segment.len > 0 and segment[0] == ':') {
                const param_name = try self.allocator.dupe(u8, segment[1..]);
                try self.param_names.append(param_name);
            }
        }
    }

    /// Match a path against this route pattern
    pub fn match(self: *const RouteMatcher, path: []const u8, method: HttpMethod) ?RouteParams {
        // Check method if specified
        if (self.method) |expected_method| {
            if (method != expected_method) return null;
        }

        // Handle wildcard routes
        if (self.is_wildcard) {
            const prefix = self.pattern[0 .. self.pattern.len - 1]; // Remove '*'
            if (std.mem.startsWith(u8, path, prefix)) {
                return RouteParams.init(self.allocator);
            }
            return null;
        }

        return self.matchPattern(path);
    }

    /// Match pattern with parameter extraction
    fn matchPattern(self: *const RouteMatcher, path: []const u8) ?RouteParams {
        var params = RouteParams.init(self.allocator);

        var pattern_segments = std.mem.splitScalar(u8, self.pattern, '/');
        var path_segments = std.mem.splitScalar(u8, path, '/');

        var param_index: usize = 0;

        while (pattern_segments.next()) |pattern_seg| {
            const path_seg = path_segments.next() orelse {
                // Pattern has more segments than path
                params.deinit();
                return null;
            };

            if (pattern_seg.len == 0) continue; // Skip empty segments

            if (pattern_seg[0] == ':') {
                // Parameter segment
                if (param_index < self.param_names.items.len) {
                    const param_name = self.param_names.items[param_index];
                    const param_value = self.allocator.dupe(u8, path_seg) catch {
                        params.deinit();
                        return null;
                    };
                    params.put(param_name, param_value) catch {
                        self.allocator.free(param_value);
                        params.deinit();
                        return null;
                    };
                    param_index += 1;
                }
            } else if (!std.mem.eql(u8, pattern_seg, path_seg)) {
                // Literal segment doesn't match
                params.deinit();
                return null;
            }
        }

        // Check if path has remaining segments
        if (path_segments.next()) |_| {
            // Path has more segments than pattern
            params.deinit();
            return null;
        }

        return params;
    }
};

/// Route definition
pub const Route = struct {
    matcher: RouteMatcher,
    handler: Handler,
    middlewares: std.ArrayList(Middleware),
    allocator: std.mem.Allocator,

    /// Initialize a route
    pub fn init(allocator: std.mem.Allocator, pattern: []const u8, method: ?HttpMethod, handler: Handler) !Route {
        return Route{
            .matcher = try RouteMatcher.init(allocator, pattern, method),
            .handler = handler,
            .middlewares = std.ArrayList(Middleware).init(allocator),
            .allocator = allocator,
        };
    }

    /// Clean up route resources
    pub fn deinit(self: *Route) void {
        self.matcher.deinit();
        self.middlewares.deinit();
    }

    /// Add middleware to this route
    pub fn use(self: *Route, middleware: Middleware) !void {
        try self.middlewares.append(middleware);
    }
};

/// Route group for organizing related routes
pub const RouteGroup = struct {
    prefix: []const u8,
    routes: std.ArrayList(Route),
    middlewares: std.ArrayList(Middleware),
    allocator: std.mem.Allocator,

    /// Initialize a route group
    pub fn init(allocator: std.mem.Allocator, prefix: []const u8) !RouteGroup {
        return RouteGroup{
            .prefix = try allocator.dupe(u8, prefix),
            .routes = std.ArrayList(Route).init(allocator),
            .middlewares = std.ArrayList(Middleware).init(allocator),
            .allocator = allocator,
        };
    }

    /// Clean up group resources
    pub fn deinit(self: *RouteGroup) void {
        self.allocator.free(self.prefix);
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit();
        self.middlewares.deinit();
    }

    /// Add route to group
    pub fn addRoute(self: *RouteGroup, pattern: []const u8, method: HttpMethod, handler: Handler) !void {
        const full_pattern = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.prefix, pattern });
        defer self.allocator.free(full_pattern);

        var route = try Route.init(self.allocator, full_pattern, method, handler);

        // Apply group middlewares to route
        for (self.middlewares.items) |middleware| {
            try route.use(middleware);
        }

        try self.routes.append(route);
    }

    /// Add middleware to group
    pub fn use(self: *RouteGroup, middleware: Middleware) !void {
        try self.middlewares.append(middleware);

        // Apply to existing routes
        for (self.routes.items) |*route| {
            try route.use(middleware);
        }
    }

    /// Convenience methods for HTTP verbs
    pub fn get(self: *RouteGroup, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .GET, handler);
    }

    pub fn post(self: *RouteGroup, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .POST, handler);
    }

    pub fn put(self: *RouteGroup, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .PUT, handler);
    }

    pub fn delete(self: *RouteGroup, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .DELETE, handler);
    }

    pub fn patch(self: *RouteGroup, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .PATCH, handler);
    }
};

/// Main router
pub const Router = struct {
    routes: std.ArrayList(Route),
    groups: std.ArrayList(RouteGroup),
    global_middlewares: std.ArrayList(Middleware),
    allocator: std.mem.Allocator,

    /// Initialize a router
    pub fn init(allocator: std.mem.Allocator) Router {
        return Router{
            .routes = std.ArrayList(Route).init(allocator),
            .groups = std.ArrayList(RouteGroup).init(allocator),
            .global_middlewares = std.ArrayList(Middleware).init(allocator),
            .allocator = allocator,
        };
    }

    /// Clean up router resources
    pub fn deinit(self: *Router) void {
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit();

        for (self.groups.items) |*route_group| {
            route_group.deinit();
        }
        self.groups.deinit();

        self.global_middlewares.deinit();
    }

    /// Add global middleware
    pub fn use(self: *Router, middleware: Middleware) !void {
        try self.global_middlewares.append(middleware);
    }

    /// Add route
    pub fn addRoute(self: *Router, pattern: []const u8, method: HttpMethod, handler: Handler) !void {
        try self.routes.append(try Route.init(self.allocator, pattern, method, handler));
    }

    /// Create route group
    pub fn group(self: *Router, prefix: []const u8) !*RouteGroup {
        try self.groups.append(try RouteGroup.init(self.allocator, prefix));
        return &self.groups.items[self.groups.items.len - 1];
    }

    /// Convenience methods for HTTP verbs
    pub fn get(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .GET, handler);
    }

    pub fn post(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .POST, handler);
    }

    pub fn put(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .PUT, handler);
    }

    pub fn delete(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .DELETE, handler);
    }

    pub fn patch(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .PATCH, handler);
    }

    pub fn head(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .HEAD, handler);
    }

    pub fn options(self: *Router, pattern: []const u8, handler: Handler) !void {
        try self.addRoute(pattern, .OPTIONS, handler);
    }

    /// Handle incoming request
    pub fn handle(self: *Router, ctx: *Context) !void {
        const path = ctx.path();
        const method = ctx.method();

        // Try to match routes
        var matched_route: ?*Route = null;
        var route_params: ?RouteParams = null;

        // Check direct routes first
        for (self.routes.items) |*route| {
            if (route.matcher.match(path, method)) |params| {
                matched_route = route;
                route_params = params;
                break;
            }
        }

        // Check group routes
        if (matched_route == null) {
            for (self.groups.items) |*route_group| {
                for (route_group.routes.items) |*route| {
                    if (route.matcher.match(path, method)) |params| {
                        matched_route = route;
                        route_params = params;
                        break;
                    }
                }
                if (matched_route != null) break;
            }
        }

        if (matched_route) |route| {
            // Set route parameters
            if (route_params) |*params| {
                var iter = params.iterator();
                while (iter.next()) |entry| {
                    try ctx.setParam(entry.key_ptr.*, entry.value_ptr.*);
                }

                // Clean up params
                var param_iter = params.iterator();
                while (param_iter.next()) |entry| {
                    self.allocator.free(entry.value_ptr.*);
                }
                params.deinit();
            }

            // Build middleware stack (global + route-specific)
            var all_middlewares = std.ArrayList(Middleware).init(self.allocator);
            defer all_middlewares.deinit();

            // Add global middlewares
            try all_middlewares.appendSlice(self.global_middlewares.items);

            // Add route-specific middlewares
            try all_middlewares.appendSlice(route.middlewares.items);

            // Execute middleware stack with route handler
            try self.executeMiddlewareStack(ctx, all_middlewares.items, route.handler);
        } else {
            // No route matched - 404
            ctx.status(.not_found);
            try ctx.text("Not Found");
        }
    }

    /// Execute middleware stack
    fn executeMiddlewareStack(_: *Router, ctx: *Context, middlewares: []const Middleware, final_handler: Handler) !void {
        // Simple sequential middleware execution for now
        // Execute all middlewares first
        for (middlewares) |middleware| {
            // Simple dummy next function that does nothing
            const dummy_next = struct {
                fn call(_: *Context) !void {}
            }.call;

            try middleware.handler(ctx, dummy_next);
        }

        // Then execute the final handler
        try final_handler(ctx);
    }

    /// Mount another router at a specific path
    pub fn mount(self: *Router, path: []const u8, other: *Router) !void {
        // Create a wildcard route that delegates to the other router
        _ = struct {
            mounted_router: *Router,
            mount_path: []const u8,

            fn handle(ctx: *Context) !void {
                const current_path = ctx.path();

                // Check if path starts with mount path
                if (std.mem.startsWith(u8, current_path, @This().mount_path)) {
                    // Create new context with adjusted path
                    const new_path = current_path[@This().mount_path.len..];

                    // Temporarily modify the context path
                    const original_path = ctx.request.uri.path;
                    ctx.request.uri.path = if (new_path.len == 0) '/' else new_path;

                    defer {
                        ctx.request.uri.path = original_path;
                    }

                    try @This().mounted_router.handle(ctx);
                } else {
                    ctx.status(.not_found);
                    try ctx.text("Not Found");
                }
            }
        };

        // This is a simplified approach - in a real implementation,
        // we'd need to properly handle the mounting
        _ = self;
        _ = path;
        _ = other;
        // TODO: Implement proper router mounting
    }
};

test "route matcher" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var matcher = try RouteMatcher.init(allocator, "/users/:id", .GET);
    defer matcher.deinit();

    // Test matching
    var params = matcher.match("/users/123", .GET);
    defer if (params) |*p| {
        var iter = p.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        p.deinit();
    };

    try testing.expect(params != null);
    try testing.expectEqualStrings("123", params.?.get("id").?);

    // Test non-matching method
    try testing.expect(matcher.match("/users/123", .POST) == null);

    // Test non-matching path
    try testing.expect(matcher.match("/posts/123", .GET) == null);
}

test "router basic functionality" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var router = Router.init(allocator);
    defer router.deinit();

    const TestHandler = struct {
        fn handle(ctx: *Context) !void {
            try ctx.text("Hello World");
        }
    };

    try router.get('/', TestHandler.handle);

    var request = @import("http/request.zig").Request.init(allocator);
    request.method = .GET;
    request.uri.path = '/';
    defer request.deinit();

    var ctx = Context.init(allocator, request);
    defer ctx.deinit();

    try router.handle(&ctx);

    try testing.expectEqualStrings("Hello World", ctx.response.body.?);
}
