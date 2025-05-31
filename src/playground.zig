// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
// const sobocrypto_aes = @import("sobocrypto_aes.zig");
// const hexed = @import("hexed.zig");
// const cli = @import("main_cli.zig");
// const cmds = @import("main_cmds.zig");

fn play1(allocator_0: std.mem.Allocator) !void {
    var xargs = std.ArrayList([]u8).init(allocator_0);
    defer xargs.deinit();

    try xargs.append(try std.fmt.allocPrint(allocator_0, "Hello", .{}));
    try xargs.append(try std.fmt.allocPrint(allocator_0, "World!", .{}));
    try xargs.append(try std.fmt.allocPrint(allocator_0, "How", .{}));
    try xargs.append(try std.fmt.allocPrint(allocator_0, "are", .{}));
    try xargs.append(try std.fmt.allocPrint(allocator_0, "you?", .{}));

    for (xargs.items) |item| {
        std.debug.print("\nITEM: {s}\n", .{item});
    }

    // std.debug.print("\nITEMS: {s}", .{xargs.items});
    // std.debug.print("\nITEM 1: {s}", .{xargs.items[1]});
    // std.debug.print("\nITEMS XXX1: {s} {s} {s} {s} {s}", xargs.items);

    // std.debug.print("\nITEMS PARAMS: {s} {s} {s} {s} {s}", .{} ++ xargs.items);

    defer {
        for (xargs.items) |item| {
            defer allocator_0.free(item);
        }
    }
}

pub fn main() !void {
    // read parameters
    var gen_purpose_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator_0 = gen_purpose_alloc.allocator();
    defer _ = gen_purpose_alloc.deinit();

    try play1(allocator_0);
    // xargs.clearAndFree();

    // const x: []u8 = try allocator_0.alloc(u8, 30);
    // defer allocator_0.free(x);
    // _ = try std.fmt.bufPrint(x, "Hello", .{});
    // // x[0] = 'H';
    // // x[1] = 'e';

    // var xargs = std.ArrayList([]u8).init(allocator_0);
    // _ = try std.fmt.bufPrint(x, "Hello", .{});
    // try xargs.append(x);
    // _ = try std.fmt.bufPrint(x, "World!", .{});
    // try xargs.append(x);
    // _ = try std.fmt.bufPrint(x, "How", .{});
    // try xargs.append(x);
    // _ = try std.fmt.bufPrint(x, "are", .{});
    // try xargs.append(x);
    // _ = try std.fmt.bufPrint(x, "you?", .{});
    // try xargs.append(x);
    // // try xargs.appendSlice("World!");
    // // try xargs.appendSlice("How");
    // // try xargs.appendSlice("are");
    // // try xargs.appendSlice("you");

    // try cli.process(allocator_0);
}
