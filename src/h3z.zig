// H3Z - Minimal, Fast, and Composable HTTP Server Framework for Zig
// Inspired by H3.js

const std = @import("std");

// Re-export core components
pub const App = @import("app.zig").App;
pub const Context = @import("context.zig").Context;
pub const Request = @import("http/request.zig").Request;
pub const Response = @import("http/response.zig").Response;
pub const Router = @import("router.zig").Router;
pub const Middleware = @import("middleware.zig").Middleware;
pub const MiddlewareStack = @import("middleware.zig").MiddlewareStack;

// HTTP types
pub const HttpMethod = @import("http/request.zig").HttpMethod;
pub const StatusCode = @import("http/status.zig").StatusCode;
pub const Headers = @import("http/request.zig").Headers;

// Utilities
pub const json = @import("utils/json.zig");
pub const url = @import("utils/url.zig");

// Built-in middleware
pub const middleware = @import("middleware.zig");
pub const cors = middleware.cors;
pub const logger = middleware.logger;
pub const bodyParser = middleware.bodyParser;

// Configuration
pub const AppConfig = @import("app.zig").AppConfig;

// Handler types
pub const Handler = @import("router.zig").Handler;
pub const NextFn = @import("middleware.zig").NextFn;

// Convenience function to create a new app
pub fn createApp(allocator: std.mem.Allocator, config: AppConfig) App {
    return App.init(allocator, config);
}

// Version info
pub const VERSION = "0.1.0";

test {
    std.testing.refAllDecls(@This());
}
