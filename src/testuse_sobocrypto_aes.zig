// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const hexed = @import("hexed.zig");
const sobocrypto_aes = @import("sobocrypto_aes.zig");
const common = @import("sobocrypto_common.zig");
const makeRandomKey = common.basic_crypto_randoms.slice_based.makeRandomKey;
const makeNonce = common.basic_crypto_randoms.slice_based.makeNonce;

pub fn main() !void {
    std.debug.print("Hello, World! Testing what's up with sobocrypto_aes...\n\n", .{});

    const key_size_bytes: comptime_int = 32;
    const nonce_size_bytes: comptime_int = 12;
    const allocator = std.heap.page_allocator;

    const buf_key_2 = try allocator.alloc(u8, key_size_bytes);
    const buf_key_2_hex = try allocator.alloc(u8, buf_key_2.len * 2);

    try makeRandomKey(buf_key_2, key_size_bytes);
    try hexed.bytesToHex(buf_key_2_hex, buf_key_2, std.fmt.Case.upper);

    const nonce_2: []u8 = try allocator.alloc(u8, nonce_size_bytes);
    try makeNonce(nonce_2, nonce_size_bytes);

    std.debug.print("\nHello there - key generated with makeRandomKey: {any}\nHEX key: {s} orig key size: {} HEX key size: {}\n", .{ buf_key_2, buf_key_2_hex, buf_key_2.len, buf_key_2_hex.len });

    const plain_text = "This is the original message to be encrypted.";
    std.debug.print("\nORIGINAL NONCE 2 {s}\n", .{std.fmt.fmtSliceHexUpper(nonce_2)});
    const aad_text = "Additional text";
    var aes_gcm_tag: [16]u8 = undefined; // GCM tag

    const encrypted_text = try allocator.alloc(u8, plain_text.len);
    const decrypted_text = try allocator.alloc(u8, plain_text.len);

    defer allocator.free(encrypted_text);
    defer allocator.free(decrypted_text);
    defer allocator.free(nonce_2);
    defer allocator.free(buf_key_2);
    defer allocator.free(buf_key_2_hex);

    try sobocrypto_aes.aesGcmEncrypt(
        encrypted_text,
        &aes_gcm_tag,
        plain_text,
        buf_key_2,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    );

    try sobocrypto_aes.aesGcmDecrypt(
        decrypted_text,
        encrypted_text,
        buf_key_2,
        aes_gcm_tag,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    );

    std.debug.print("\n====> encrypted text: {any}\n--> ENC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{
        encrypted_text,
        std.fmt.fmtSliceHexUpper(encrypted_text),
        aes_gcm_tag,
        std.fmt.fmtSliceHexUpper(&aes_gcm_tag),
    });

    std.debug.print("\n====> decrypted text: {s}\nANY: {any}\n--> DEC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{
        decrypted_text,
        decrypted_text,
        std.fmt.fmtSliceHexUpper(decrypted_text),
        aes_gcm_tag,
        std.fmt.fmtSliceHexUpper(&aes_gcm_tag),
    });
}
