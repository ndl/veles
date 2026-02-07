const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("veles", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "veles",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .strip = true,
            .link_libc = true,
            .imports = &.{
                .{ .name = "veles", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const zigcli = b.dependency("zigcli", .{});
    exe.root_module.addImport("simargs", zigcli.module("simargs"));
    exe.root_module.linkSystemLibrary("keyutils", .{ .preferred_link_mode = .static });

    const ziglangSet = b.dependency("ziglangSet", .{});
    mod.addImport("ziglangSet", ziglangSet.module("ziglangSet"));
}
