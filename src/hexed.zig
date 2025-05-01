const std = @import("std");

// taken from /snap/zig/13822/lib/std/fmt.zig AND FIXED. In the original form it
// was useless, because it runtime-calculated the return value, which is forbidden
// and was a cause of the error ""
///snap/zig/13822/lib/std/fmt.zig:2459:53: error: unable to evaluate comptime expression
//pub fn bytesToHex(input: anytype, case: Case) [input.len * 2]u8 {
//                                               ~~~~~^~~~

pub fn bytesToHex(output: []u8, input: anytype, case: std.fmt.Case) !void {
    if (input.len == 0) {
        return;
    }
    comptime std.debug.assert(@TypeOf(input[0]) == u8); // elements to encode must be unsigned bytes

    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";
    // var result: [input.len * 2]u8 = undefined;
    for (input, 0..) |b, i| {
        output[i * 2 + 0] = charset[b >> 4];
        output[i * 2 + 1] = charset[b & 15];
    }
}

/// TAKEN  from /snap/zig/13822/lib/std/fmt.zig just to accompany the
/// counterpart bytesToHex in the proper version.
/// Decodes the sequence of bytes represented by the specified string of
/// hexadecimal characters.
/// Returns a slice of the output buffer containing the decoded bytes.
pub fn hexToBytes(out: []u8, input: []const u8) ![]u8 {
    // Expect 0 or n pairs of hexadecimal digits.
    if (input.len & 1 != 0)
        return error.InvalidLength;
    if (out.len * 2 < input.len)
        return error.NoSpaceLeft;
    if (input.len % 2 != 0) return error.InvalidHexString;

    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += 2) {
        const hi = try std.fmt.charToDigit(input[in_i], 16);
        const lo = try std.fmt.charToDigit(input[in_i + 1], 16);
        out[in_i / 2] = (hi << 4) | lo;
    }

    return out[0 .. in_i / 2];
}

// taken from /snap/zig/13822/lib/std/fmt.zig AND ADJUSTED to return-via-parameter
test bytesToHex {
    const input = "input slice";
    const allocator = std.heap.page_allocator;
    const encoded = try allocator.alloc(u8, input.len * 2);
    try bytesToHex(encoded, input, std.fmt.Case.upper);

    var decoded: [input.len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, input, try hexToBytes(&decoded, encoded));
}

// taken from /snap/zig/13822/lib/std/fmt.zig, unchanged
test hexToBytes {
    var buf: [32]u8 = undefined;
    try std.testing.expectFmt("90" ** 32, "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, "90" ** 32))});
    try std.testing.expectFmt("ABCD", "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, "ABCD"))});
    try std.testing.expectFmt("", "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, ""))});
    try std.testing.expectError(error.InvalidCharacter, hexToBytes(&buf, "012Z"));
    try std.testing.expectError(error.InvalidLength, hexToBytes(&buf, "AAA"));
    try std.testing.expectError(error.NoSpaceLeft, hexToBytes(buf[0..1], "ABAB"));
}
