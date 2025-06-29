const std = @import("std");

/// HTTP status codes
pub const StatusCode = enum(u16) {
    // 1xx Informational
    continue_ = 100,
    switching_protocols = 101,
    processing = 102,
    early_hints = 103,

    // 2xx Success
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,
    multi_status = 207,
    already_reported = 208,
    im_used = 226,

    // 3xx Redirection
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // 4xx Client Error
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    im_a_teapot = 418,
    misdirected_request = 421,
    unprocessable_entity = 422,
    locked = 423,
    failed_dependency = 424,
    too_early = 425,
    upgrade_required = 426,
    precondition_required = 428,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    unavailable_for_legal_reasons = 451,

    // 5xx Server Error
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    not_extended = 510,
    network_authentication_required = 511,

    /// Get the reason phrase for a status code
    pub fn phrase(self: StatusCode) []const u8 {
        return switch (self) {
            .continue_ => "Continue",
            .switching_protocols => "Switching Protocols",
            .processing => "Processing",
            .early_hints => "Early Hints",

            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multi_status => "Multi-Status",
            .already_reported => "Already Reported",
            .im_used => "IM Used",

            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",

            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .im_a_teapot => "I'm a teapot",
            .misdirected_request => "Misdirected Request",
            .unprocessable_entity => "Unprocessable Entity",
            .locked => "Locked",
            .failed_dependency => "Failed Dependency",
            .too_early => "Too Early",
            .upgrade_required => "Upgrade Required",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .unavailable_for_legal_reasons => "Unavailable For Legal Reasons",

            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            .variant_also_negotiates => "Variant Also Negotiates",
            .insufficient_storage => "Insufficient Storage",
            .loop_detected => "Loop Detected",
            .not_extended => "Not Extended",
            .network_authentication_required => "Network Authentication Required",
        };
    }

    /// Check if status code is informational (1xx)
    pub fn isInformational(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 100 and code < 200;
    }

    /// Check if status code indicates success (2xx)
    pub fn isSuccess(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 200 and code < 300;
    }

    /// Check if status code indicates redirection (3xx)
    pub fn isRedirection(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 300 and code < 400;
    }

    /// Check if status code indicates client error (4xx)
    pub fn isClientError(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 400 and code < 500;
    }

    /// Check if status code indicates server error (5xx)
    pub fn isServerError(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 500 and code < 600;
    }

    /// Check if status code indicates error (4xx or 5xx)
    pub fn isError(self: StatusCode) bool {
        return self.isClientError() or self.isServerError();
    }
};

test "status code properties" {
    const testing = std.testing;

    try testing.expect(StatusCode.ok.isSuccess());
    try testing.expect(StatusCode.not_found.isClientError());
    try testing.expect(StatusCode.internal_server_error.isServerError());
    try testing.expect(StatusCode.not_found.isError());
    try testing.expect(!StatusCode.ok.isError());

    try testing.expectEqualStrings("OK", StatusCode.ok.phrase());
    try testing.expectEqualStrings("Not Found", StatusCode.not_found.phrase());
}
