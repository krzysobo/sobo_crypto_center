// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");

fn testAlloc(allocator: std.mem.Allocator) ![]u8 {
    const rest: []u8 = try allocator.alloc(u8, 437);
    _ = try std.fmt.bufPrint(rest, "LORDE ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est ", .{});
    // try std.mem.copyForwards(u8, rest, "Lorem Ipsum Dolor Sit Amet");
    // defer free(rest);
    return rest;
}

fn testAlloc2(allocator: std.mem.Allocator) ![]u8 {
    // var gen_purpose_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // const allocator = gen_purpose_alloc.allocator();
    const rest: []u8 = try allocator.alloc(u8, 441);
    _ = try std.fmt.bufPrint(rest, "WORED ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est labo", .{});
    // try std.mem.copyForwards(u8, rest, "Lorem Ipsum Dolor Sit Amet");
    return rest;
}

fn testAlloc3() ![]u8 {
    const allocator = std.heap.page_allocator;
    const rest: []u8 = try allocator.alloc(u8, 450);
    _ = try std.fmt.bufPrint(rest, "BORED ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.GAMMA", .{});
    // try std.mem.copyForwards(u8, rest, "Lorem Ipsum Dolor Sit Amet");
    return rest;
}
fn testNonAlloc1(sajz: comptime_int) ![sajz]u8 {
    var rest: [sajz]u8 = undefined;
    _ = try std.fmt.bufPrint(&rest, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.", .{});
    return rest;
}

pub fn main() !void {
    // read parameters
    var gen_purpose_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator_0 = gen_purpose_alloc.allocator();
    const allocator_1 = std.heap.page_allocator;

    defer _ = gen_purpose_alloc.deinit();
    // _ = allocator_0;

    for (1..100000) |i| {
        std.debug.print("\nI: {}", .{i});
        const rest = try testAlloc(allocator_0);
        const rest_2 = try testAlloc2(allocator_1);
        const rest_3 = try testAlloc3();
        const rest_4 = try testNonAlloc1(445);
        std.debug.print("\nREST IS: {s} \n", .{rest});
        std.debug.print("\nREST_2 IS: {s} \n", .{rest_2});
        std.debug.print("\nREST_3 IS: {s} \n", .{rest_3});
        std.debug.print("\nREST_4 IS: {s} \n", .{rest_4});

        defer allocator_0.free(rest);
        defer allocator_1.free(rest_2);
        defer allocator_1.free(rest_3);
    }
}
