// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const hexed = @import("hexed.zig");
const common = @import("sobocrypto_common.zig");

pub const PortableKeySuite = struct {
    pub const sep_size_bytes: comptime_int = 5; // 'W' + key + 'Q' + tag + 'Q' + nonce + 'Q' + aad + 'W'
    pub const key_size_bytes: comptime_int = 32;
    pub const nonce_size_bytes: comptime_int = 12;
    pub const tag_size_bytes: comptime_int = 16;

    pub const aad_text = "Dolor sit amet."; // additional text for authentication; for now, it's a constant text

    // port_buf_out: [] u8,
    key_buf_in: []const u8,
    tag_buf_in: []const u8,
    nonce_buf_in: []const u8,
    aad_buf_in: []const u8,

    pub fn init(
        key_buf_in: []const u8,
        tag_buf_in: []const u8,
        nonce_buf_in: []const u8,
        aad_buf_in: []const u8,
    ) PortableKeySuite {
        return PortableKeySuite{
            .key_buf_in = key_buf_in,
            .tag_buf_in = tag_buf_in,
            .nonce_buf_in = nonce_buf_in,
            .aad_buf_in = aad_buf_in,
        };
    }

    pub fn getHexStringKeySizeConst() usize {
        return PortableKeySuite.sep_size_bytes + (PortableKeySuite.key_size_bytes +
            PortableKeySuite.nonce_size_bytes +
            PortableKeySuite.tag_size_bytes +
            PortableKeySuite.aad_text.len) * 2;
    }

    pub fn getHexStringSize(self: *PortableKeySuite) usize {
        return self.key_buf_in.len * 2 +
            self.tag_buf_in.len * 2 +
            self.nonce_buf_in.len * 2 +
            self.aad_buf_in.len * 2 +
            PortableKeySuite.sep_size_bytes;
    }

    // 'W' + key_buf_hex + 'Q' + tag_buf_hex + 'Q' + nonce_buf_hex + 'Q' + aad_buf_hex + 'W'
    pub fn getHexString(self: *PortableKeySuite, buf_out: []u8) !void {
        return makePortableKeySuite(
            buf_out,
            self.key_buf_in,
            self.tag_buf_in,
            self.nonce_buf_in,
            self.aad_buf_in,
            PortableKeySuite.sep_size_bytes,
        );
    }

    // 'W' + key_buf_hex + 'Q' + tag_buf_hex + 'Q' + nonce_buf_hex + 'Q' + aad_buf_hex + 'W'
    pub fn initFromHexString(buf_hex_pks: []const u8) !PortableKeySuite {
        var key_buf_in: []u8 = undefined;
        var tag_buf_in: []u8 = undefined;
        var nonce_buf_in: []u8 = undefined;
        var aad_buf_in: []u8 = undefined;

        // std.debug.print("\n initFromHexString::: string::: {s}\n", .{buf_hex_pks});

        if (!std.mem.startsWith(u8, buf_hex_pks, "W") or !std.mem.endsWith(u8, buf_hex_pks, "W")) {
            return error.InvalidPortableKeyFormat;
        }

        // std.debug.print("\n initFromHexString::: string-2::: {s}\n", .{buf_hex_pks});

        const buf_hex_pks_trimmed = std.mem.trim(u8, buf_hex_pks, "W");
        const allocator = std.heap.page_allocator;

        // std.debug.print("\nHEX: {s}\nHEX TRIMMED: {s}\n\n", .{buf_hex_pks, buf_hex_pks_trimmed});

        var it = std.mem.splitScalar(u8, buf_hex_pks_trimmed, 'Q');
        const it_first = it.first();
        key_buf_in = try allocator.alloc(u8, it_first.len / 2);
        _ = try hexed.hexToBytes(key_buf_in, it_first);

        // std.debug.print("\nIT FIRST: {s} \n\n", .{it_first});

        var i: u8 = 0;
        while (it.next()) |val| {
            // std.debug.print("\n== I: {} VAL: {s}", .{i, val});
            if (i == 0) {
                tag_buf_in = try allocator.alloc(u8, val.len / 2);
                _ = try hexed.hexToBytes(tag_buf_in, val);
            } else if (i == 1) {
                nonce_buf_in = try allocator.alloc(u8, val.len / 2);
                _ = try hexed.hexToBytes(nonce_buf_in, val);
            } else if (i == 2) {
                aad_buf_in = try allocator.alloc(u8, val.len / 2);
                _ = try hexed.hexToBytes(aad_buf_in, val);
            }
            i += 1;
        }

        // std.debug.print("FINAL I: {}\n\n", .{i});
        if (i != 3) {
            return error.InvalidPortableKeyFormat;
        }

        return PortableKeySuite.init(key_buf_in, tag_buf_in, nonce_buf_in, aad_buf_in);
    }
};

pub fn makePortableKeySuite(port_buf_out: []u8, key_buf_in: []const u8, tag_buf_in: []const u8, nonce_buf_in: []const u8, aad_buf_in: []const u8, sep_size_bytes: comptime_int) !void {
    const allocator = std.heap.page_allocator;

    const key_buf_hex: []u8 = try allocator.alloc(u8, key_buf_in.len * 2);
    const tag_buf_hex: []u8 = try allocator.alloc(u8, tag_buf_in.len * 2);
    const nonce_buf_hex: []u8 = try allocator.alloc(u8, nonce_buf_in.len * 2);
    const aad_buf_hex: []u8 = try allocator.alloc(u8, aad_buf_in.len * 2);

    defer allocator.free(key_buf_hex);
    defer allocator.free(tag_buf_hex);
    defer allocator.free(nonce_buf_hex);
    defer allocator.free(aad_buf_hex);

    try hexed.bytesToHex(key_buf_hex, key_buf_in, std.fmt.Case.upper);
    try hexed.bytesToHex(tag_buf_hex, tag_buf_in, std.fmt.Case.upper);
    try hexed.bytesToHex(nonce_buf_hex, nonce_buf_in, std.fmt.Case.upper);
    try hexed.bytesToHex(aad_buf_hex, aad_buf_in, std.fmt.Case.upper);

    // std.debug.print("PKS size: {}, KEY size: {}, TAG size: {}, NONCE size: {}, AAD size: {} + 3", .{port_buf_out.len, key_buf_in.len, tag_buf_in.len, nonce_buf_in.len, aad_buf_in.len});

    const all_len = key_buf_hex.len + tag_buf_hex.len + nonce_buf_hex.len + aad_buf_hex.len + sep_size_bytes;

    if (all_len != port_buf_out.len) return error.InvalidComponentsLength;

    _ = try std.fmt.bufPrint(port_buf_out, "W{s}Q{s}Q{s}Q{s}W", .{ key_buf_hex, tag_buf_hex, nonce_buf_hex, aad_buf_hex });

    std.debug.print("PKS: {s}\n--KEY BUF HEX: {s}\n--TAG BUF HEX: {s}\n--NONCE BUF HEX: {s}\n--AAD_BUF_HEX: {s}\n\n", .{ port_buf_out, key_buf_hex, tag_buf_hex, nonce_buf_hex, aad_buf_hex });
}
