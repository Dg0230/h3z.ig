const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // H3Z library
    const h3z_lib = b.addStaticLibrary(.{
        .name = "h3z",
        .root_source_file = b.path("src/h3z.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(h3z_lib);

    // H3Z module for other projects
    const h3z_module = b.addModule("h3z", .{
        .root_source_file = b.path("src/h3z.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Examples

    // Basic server example
    const basic_example = b.addExecutable(.{
        .name = "basic_server",
        .root_source_file = b.path("examples/basic_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_example.root_module.addImport("h3z", h3z_module);
    b.installArtifact(basic_example);

    const run_basic = b.addRunArtifact(basic_example);
    run_basic.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_basic.addArgs(args);
    }

    const run_basic_step = b.step("run-basic", "Run the basic server example");
    run_basic_step.dependOn(&run_basic.step);

    // Tests
    const h3z_tests = b.addTest(.{
        .root_source_file = b.path("src/h3z.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(h3z_tests);
    const test_step = b.step("test", "Run H3Z tests");
    test_step.dependOn(&run_tests.step);

    // Individual module tests
    const modules = [_][]const u8{
        "src/http/status.zig",
        "src/http/request.zig",
        "src/http/response.zig",
        "src/context.zig",
        "src/middleware.zig",
        "src/router.zig",
        "src/app.zig",
    };

    for (modules) |module| {
        const module_test = b.addTest(.{
            .root_source_file = b.path(module),
            .target = target,
            .optimize = optimize,
        });

        const run_module_test = b.addRunArtifact(module_test);
        test_step.dependOn(&run_module_test.step);
    }

    // Benchmarks
    const benchmark_exe = b.addExecutable(.{
        .name = "h3z_benchmark",
        .root_source_file = b.path("benchmarks/basic_benchmark.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    benchmark_exe.root_module.addImport("h3z", h3z_module);
    b.installArtifact(benchmark_exe);

    const run_benchmark = b.addRunArtifact(benchmark_exe);
    const benchmark_step = b.step("benchmark", "Run H3Z benchmarks");
    benchmark_step.dependOn(&run_benchmark.step);

    // Documentation
    const docs = b.addTest(.{
        .root_source_file = b.path("src/h3z.zig"),
        .target = target,
        .optimize = optimize,
    });

    const docs_step = b.step("docs", "Generate H3Z documentation");
    docs_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = docs.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    }).step);

    // Code formatting
    const fmt_step = b.step("fmt", "Format H3Z source code");
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "examples", "benchmarks" },
        .check = false,
    });
    fmt_step.dependOn(&fmt.step);

    // Code checking
    const check_step = b.step("check", "Check H3Z source code formatting");
    const check_fmt = b.addFmt(.{
        .paths = &.{ "src", "examples", "benchmarks" },
        .check = true,
    });
    check_step.dependOn(&check_fmt.step);

    // Clean
    const clean_step = b.step("clean", "Clean build artifacts");
    const clean_exe = b.addSystemCommand(&.{ "rm", "-rf", "zig-cache", "zig-out" });
    clean_step.dependOn(&clean_exe.step);

    // Development server with auto-reload
    const dev_step = b.step("dev", "Run development server with auto-reload");
    const dev_script = b.addSystemCommand(&.{ "zig", "build", "run-basic" });
    dev_step.dependOn(&dev_script.step);

    // Install step with all artifacts
    const install_step = b.getInstallStep();
    install_step.dependOn(&b.addInstallArtifact(h3z_lib, .{}).step);
    install_step.dependOn(&b.addInstallArtifact(basic_example, .{}).step);
    install_step.dependOn(&b.addInstallArtifact(benchmark_exe, .{}).step);

    // Default step
    b.default_step = install_step;
}
