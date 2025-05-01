const std = @import("std");
const hexed = @import("hexed.zig");

pub fn main() !void {
    std.debug.print("Hello, World! Co tam słychać??\n\n", .{});

    const source_str: []const u8 = "Alfa beta gamma delta";

    const allocator = std.heap.page_allocator;
    const buf_uc = try allocator.alloc(u8, source_str.len * 2);
    const buf_lc = try allocator.alloc(u8, source_str.len * 2);
    const buf_ret_uc: []u8 = try allocator.alloc(u8, source_str.len);
    const buf_ret_lc: []u8 = try allocator.alloc(u8, source_str.len);
    try hexed.bytesToHex(buf_uc, source_str, std.fmt.Case.upper);
    try hexed.bytesToHex(buf_lc, source_str, std.fmt.Case.lower);

    _ = try hexed.hexToBytes(buf_ret_uc, buf_uc);
    _ = try hexed.hexToBytes(buf_ret_lc, buf_lc);

    std.debug.print("Source: {s}\n\n", .{source_str});
    std.debug.print("BUF_LC: {s}\n\n", .{buf_lc});
    std.debug.print("BUF_UC: {s}\n\n", .{buf_uc});
    std.debug.print("BUF_RET_LC: {s}\n\n", .{buf_ret_lc});
    std.debug.print("BUF_RET_UC: {s}\n\n", .{buf_ret_uc});

    std.debug.assert(std.mem.eql(u8, buf_ret_lc, source_str));
    std.debug.assert(std.mem.eql(u8, buf_ret_uc, source_str));
}
