const std = @import("std");

// taken from /snap/zig/13822/lib/std/fmt.zig AND changed to buf-outputting form.
// encodes the sequence of bytes to hex format, lower or uppercase,
// depending on the "case" parameter
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

pub fn bytesToHexAlloc(input: anytype, case: std.fmt.Case, allocator: std.mem.Allocator) ![]u8 {
    if (input.len == 0) {
        return "";
    }

    const len_hex = input.len * 2;
    const output = try allocator.alloc(u8, len_hex);
    comptime std.debug.assert(@TypeOf(input[0]) == u8); // elements to encode must be unsigned bytes

    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";
    // var result: [input.len * 2]u8 = undefined;
    for (input, 0..) |b, i| {
        output[i * 2 + 0] = charset[b >> 4];
        output[i * 2 + 1] = charset[b & 15];
    }
    return output;
}
/// TAKEN  from /snap/zig/13822/lib/std/fmt.zig just to accompany the
/// counterpart bytesToHex.Z
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

pub fn hexToBytesAlloc(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Expect 0 or n pairs of hexadecimal digits.
    if (input.len & 1 != 0) return error.InvalidLength;
    if (input.len % 2 != 0) return error.InvalidHexString;

    const len_hex = input.len;
    const len_bytes = len_hex / 2;
    const output = try allocator.alloc(u8, len_bytes);

    var in_i: usize = 0;
    while (in_i < input.len) : (in_i += 2) {
        const hi = try std.fmt.charToDigit(input[in_i], 16);
        const lo = try std.fmt.charToDigit(input[in_i + 1], 16);
        output[in_i / 2] = (hi << 4) | lo;
    }

    return output[0 .. in_i / 2];
}

// taken from /snap/zig/13822/lib/std/fmt.zig AND ADJUSTED to return-via-parameter
test "bytesToHex and hexToBytes" {
    const input = "input slice";
    const allocator = std.heap.page_allocator;
    const encoded = try allocator.alloc(u8, input.len * 2);
    try bytesToHex(encoded, input, std.fmt.Case.upper);

    var decoded: [input.len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, input, try hexToBytes(&decoded, encoded));
}

// taken from /snap/zig/13822/lib/std/fmt.zig, unchanged
test "hexToBytes and std fmtSliceHexUpper" {
    var buf: [32]u8 = undefined;
    try std.testing.expectFmt("90" ** 32, "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, "90" ** 32))});
    try std.testing.expectFmt("ABCD", "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, "ABCD"))});
    try std.testing.expectFmt("", "{s}", .{std.fmt.fmtSliceHexUpper(try hexToBytes(&buf, ""))});
    try std.testing.expectError(error.InvalidCharacter, hexToBytes(&buf, "012Z"));
    try std.testing.expectError(error.InvalidLength, hexToBytes(&buf, "AAA"));
    try std.testing.expectError(error.NoSpaceLeft, hexToBytes(buf[0..1], "ABAB"));
}

test bytesToHexAlloc {
    const allocator = std.heap.page_allocator;
    const input = "ABCXYZ";
    const test_output = "41424358595A"; // ABCXYZ

    const res = try bytesToHexAlloc(
        input,
        std.fmt.Case.upper,
        allocator,
    );
    defer allocator.free(res);

    try std.testing.expect(std.mem.eql(u8, res, test_output));
}

test hexToBytesAlloc {
    const allocator = std.heap.page_allocator;
    const input = "41424358595A"; // ABC
    const test_output = "ABCXYZ";

    const res = try hexToBytesAlloc(input, allocator);
    defer allocator.free(res);

    try std.testing.expect(std.mem.eql(u8, res, test_output));

    // const our_dh_priv_key_bytes: []u8 = try allocator.alloc(u8, sobocrypto_dh.SizesDh.dh_private_key);

}
