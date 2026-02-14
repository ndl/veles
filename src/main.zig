// Veles is a tool to setup and use TPM-based ZFS datasets encryption.
//
// Copyright (C) 2026 Alexander Tsvyashchenko <veles@endl.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Main entry point to Veles.

const std = @import("std");
const simargs = @import("simargs");
const veles = @import("veles");

pub const std_options: std.Options = .{
    .logFn = velesLogFn,
    // Make sure all the messages get to `velesLogFn`,
    // we'll filter them out inside.
    .log_level = .debug,
};

// Default log level to use, as `std.options.log_level` doesn't
// allow us to override it at runtime.
var log_level = std.log.Level.info;

pub fn velesLogFn(
    comptime level: std.log.Level,
    comptime _: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(log_level)) {
        return;
    }
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.fs.File.stderr().deprecatedWriter();
    nosuspend stderr.print(format ++ "\n", args) catch return;
}

const Commands = union(enum) {
    setup: veles.setup.Options,
    load: veles.load.Options,
    verify: veles.verify.Options,

    pub const __messages__ = .{
        .setup = "Setup ZFS verification",
        .load = "Load ZFS key (if initial verification is successful)",
        .verify = "Verify encrypted ZFS datasets (after mount)",
    };
};

const Options = struct {
    debug: bool = false,
    help: bool = false,
    leaks: bool = false,
    version: bool = false,
    __commands__: Commands,

    pub const __shorts__ = .{
        .debug = .d,
        .help = .h,
        .leaks = .l,
    };

    pub const __messages__ = .{
        .debug = "Output debug information and don't shutdown if verification failed, NOT SECURE!",
        .leaks = "If true - turn on debug allocator leaks detection",
    };
};

fn run(comptime OptsType: type, allocator: std.mem.Allocator, opts: OptsType) !void {
    switch (opts.args.__commands__) {
        Commands.setup => |value| try veles.setup.run(allocator, value),
        Commands.load => |value| try veles.load.run(allocator, value),
        Commands.verify => |value| try veles.verify.run(allocator, value),
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator: std.mem.Allocator = arena.allocator();

    var opts = try simargs.parse(allocator, Options, "[file]", "0.3.6");
    defer opts.deinit();

    if (opts.args.debug) {
        veles.common.debug = true;
        log_level = std.log.Level.debug;
    }

    if (opts.args.leaks) {
        var gpa: std.heap.DebugAllocator(.{}) = .init;
        defer {
            const deinit_status = gpa.deinit();
            if (deinit_status == .leak) @panic("ALLOCATOR ERROR");
        }
        try run(@TypeOf(opts), gpa.allocator(), opts);
    } else {
        try run(@TypeOf(opts), allocator, opts);
    }
}
