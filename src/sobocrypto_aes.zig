// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const hexed = @import("hexed.zig");
const common = @import("sobocrypto_common.zig");
const sobocrypto_pks = @import("sobocrypto_aes_pks.zig");
const makeRandomKey = common.basic_crypto_randoms.slice_based.makeRandomKey;
const makeNonce = common.basic_crypto_randoms.slice_based.makeNonce;

pub fn aesGcmEncrypt(
    output_ciphertext: []u8,
    output_aes_gcm_tag: *[16]u8,
    input_plaintext: []const u8,
    cipher_key: []const u8,
    nonce: []const u8,
    aad_text: []const u8,
    nonce_size_bytes: comptime_int,
    cipher_key_size_bytes: comptime_int,
) !void {
    if (cipher_key.len != cipher_key_size_bytes) return error.InvalidKeyLength;
    if (nonce.len != nonce_size_bytes) return error.InvalidNonceLength;
    if (output_ciphertext.len != input_plaintext.len) return error.InvalidCiphertextLength;

    var nonce_out: [nonce_size_bytes]u8 = nonce[0..nonce_size_bytes].*;
    var cipher_key_out: [cipher_key_size_bytes]u8 = cipher_key[0..cipher_key_size_bytes].*;

    if (!std.mem.eql(u8, nonce, &nonce_out)) return error.InvalidNonceCopy;
    if (!std.mem.eql(u8, cipher_key, &cipher_key_out)) return error.InvalidCipherKeyCopy;

    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(output_ciphertext, output_aes_gcm_tag, input_plaintext, aad_text, nonce_out, cipher_key_out);
}

pub fn aesGcmDecrypt(
    output_plain_text: []u8,
    input_ciphertext: []const u8,
    input_cipher_key: []const u8,
    input_aes_gcm_tag: [16]u8,
    input_nonce: []const u8,
    aad_text: []const u8,
    nonce_size_bytes: comptime_int,
    cipher_key_size_bytes: comptime_int,
) !void {
    const nonce_out: [nonce_size_bytes]u8 = input_nonce[0..nonce_size_bytes].*;
    const cipher_key_out: [cipher_key_size_bytes]u8 = input_cipher_key[0..cipher_key_size_bytes].*;

    return std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        output_plain_text,
        input_ciphertext,
        input_aes_gcm_tag,
        aad_text,
        nonce_out,
        cipher_key_out,
    );
}

// ======================================== HEX interface =======================================================
pub fn aesGcmDecryptFromHex(
    decrypted_text: []u8,
    ciphertext_hex: []u8,
    hex_key_suite: []u8,
) !void {
    const key_size_bytes: comptime_int = sobocrypto_pks.PortableKeySuite.key_size_bytes;
    const nonce_size_bytes: comptime_int = sobocrypto_pks.PortableKeySuite.nonce_size_bytes;

    if (ciphertext_hex.len % 2 != 0) {
        return error.InvalidCiphertextLength;
    }

    const allocator = std.heap.page_allocator;
    const ciphertext_bytes = try allocator.alloc(u8, ciphertext_hex.len / 2);
    _ = try hexed.hexToBytes(ciphertext_bytes, ciphertext_hex);

    const pks_struct = try sobocrypto_pks.PortableKeySuite.initFromHexString(hex_key_suite);
    const tag_buf_out: [16]u8 = pks_struct.tag_buf_in[0..16].*;

    return aesGcmDecrypt(decrypted_text, ciphertext_bytes, pks_struct.key_buf_in, tag_buf_out, pks_struct.nonce_buf_in, pks_struct.aad_buf_in, nonce_size_bytes, key_size_bytes);
}

pub fn aesGcmEncryptToHex(
    output_ciphertext_hex: []u8,
    output_keysuite: []u8,
    in_plain_text: []u8,
) !void {
    const allocator = std.heap.page_allocator;
    const key_size_bytes: comptime_int = sobocrypto_pks.PortableKeySuite.key_size_bytes;
    const nonce_size_bytes: comptime_int = sobocrypto_pks.PortableKeySuite.nonce_size_bytes;

    const buf_key = try allocator.alloc(u8, key_size_bytes);
    const nonce: []u8 = try allocator.alloc(u8, nonce_size_bytes);
    const buf_ciphertext: []u8 = try allocator.alloc(u8, in_plain_text.len);

    defer allocator.free(nonce);
    defer allocator.free(buf_key);
    defer allocator.free(buf_ciphertext);

    try makeRandomKey(buf_key, key_size_bytes);
    try makeNonce(nonce, nonce_size_bytes);

    const aad_text = sobocrypto_pks.PortableKeySuite.aad_text; // additional text for authentication
    var aes_gcm_tag: [16]u8 = undefined; // GCM tag

    try aesGcmEncrypt(
        buf_ciphertext,
        &aes_gcm_tag,
        in_plain_text,
        buf_key,
        nonce,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    );

    var pks_inst = sobocrypto_pks.PortableKeySuite.init(
        buf_key,
        &aes_gcm_tag,
        nonce,
        aad_text,
    );
    try pks_inst.getHexString(output_keysuite);

    try hexed.bytesToHex(output_ciphertext_hex, buf_ciphertext, std.fmt.Case.upper);
}
// ======================================== /HEX interface =======================================================

// ======================================= tests =====================================

test " common. makeRandomKey " {
    const key_size: comptime_int = 32;
    const allocator = std.heap.page_allocator;
    const buf_key_2 = try allocator.alloc(u8, key_size);
    const buf_key_2_hex = try allocator.alloc(u8, buf_key_2.len * 2);
    const buf_key_3 = try allocator.alloc(u8, key_size);

    try makeRandomKey(buf_key_2, key_size);
    try hexed.bytesToHex(buf_key_2_hex, buf_key_2, std.fmt.Case.upper);
    try std.testing.expectEqual(buf_key_2.len, key_size);
    try std.testing.expectEqual(buf_key_2_hex.len, key_size * 2);

    const res_make_random_key_error = makeRandomKey(buf_key_3, key_size + 3);

    try std.testing.expectError(error.InvalidSize, res_make_random_key_error);
}

test " makeNonce " {
    const key_size: comptime_int = 32;
    const allocator = std.heap.page_allocator;
    const buf_key_2 = try allocator.alloc(u8, key_size);
    const buf_key_2_hex = try allocator.alloc(u8, buf_key_2.len * 2);
    const buf_key_3 = try allocator.alloc(u8, key_size);

    try makeNonce(buf_key_2, key_size);
    try hexed.bytesToHex(buf_key_2_hex, buf_key_2, std.fmt.Case.upper);
    try std.testing.expectEqual(buf_key_2.len, key_size);
    try std.testing.expectEqual(buf_key_2_hex.len, key_size * 2);

    const res_make_random_key_error = makeRandomKey(buf_key_3, key_size + 3);

    try std.testing.expectError(error.InvalidSize, res_make_random_key_error);
}

test "encryption and decryption process" {
    const key_size_bytes: comptime_int = 32;
    const nonce_size_bytes: comptime_int = 12;
    const sep_size_bytes: comptime_int = 5;
    const allocator = std.heap.page_allocator;

    const buf_key_2 = try allocator.alloc(u8, key_size_bytes);
    const buf_key_2_hex = try allocator.alloc(u8, buf_key_2.len * 2);

    try makeRandomKey(buf_key_2, key_size_bytes);
    try hexed.bytesToHex(buf_key_2_hex, buf_key_2, std.fmt.Case.upper);

    try std.testing.expectEqual(buf_key_2.len, key_size_bytes);
    try std.testing.expectEqual(buf_key_2_hex.len, key_size_bytes * 2);

    const nonce_2: []u8 = try allocator.alloc(u8, nonce_size_bytes);
    try makeNonce(nonce_2, nonce_size_bytes);

    std.debug.print("\nHello there - key generated with makeRandomKey: {any}\nHEX key: {s} orig key size: {} HEX key size: {}\n", .{ buf_key_2, buf_key_2_hex, buf_key_2.len, buf_key_2_hex.len });

    const plain_text = "This is the original message to be encrypted. Lorem ipsum";
    std.debug.print("\nORIGINAL NONCE 2 {s}\n", .{std.fmt.fmtSliceHexUpper(nonce_2)});
    const aad_text = sobocrypto_pks.PortableKeySuite.aad_text;
    var aes_gcm_tag: [16]u8 = undefined; // GCM tag

    const encrypted_text = try allocator.alloc(u8, plain_text.len);
    const decrypted_text = try allocator.alloc(u8, plain_text.len);

    defer allocator.free(encrypted_text);
    defer allocator.free(decrypted_text);
    defer allocator.free(nonce_2);
    defer allocator.free(buf_key_2);
    defer allocator.free(buf_key_2_hex);

    try aesGcmEncrypt(
        encrypted_text,
        &aes_gcm_tag,
        plain_text,
        buf_key_2,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    );

    const buf_key_3_error = try allocator.alloc(u8, key_size_bytes + 5);
    const plain_text_error = "Wrong length of text";

    try std.testing.expectError(error.InvalidKeyLength, aesGcmEncrypt(
        encrypted_text,
        &aes_gcm_tag,
        plain_text,
        buf_key_3_error,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    ));

    try std.testing.expectError(error.InvalidCiphertextLength, aesGcmEncrypt(
        encrypted_text,
        &aes_gcm_tag,
        plain_text_error,
        buf_key_2,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    ));

    try aesGcmDecrypt(
        decrypted_text,
        encrypted_text,
        buf_key_2,
        aes_gcm_tag,
        nonce_2,
        aad_text,
        nonce_size_bytes,
        key_size_bytes,
    );
    std.debug.print("\n====> encrypted text: {any}\n--> ENC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{ encrypted_text, std.fmt.fmtSliceHexUpper(encrypted_text), aes_gcm_tag, std.fmt.fmtSliceHexUpper(
        &aes_gcm_tag,
    ) });
    std.debug.print("\n====> decrypted text: {s}\nANY: {any}\n--> DEC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{ decrypted_text, decrypted_text, std.fmt.fmtSliceHexUpper(decrypted_text), aes_gcm_tag, std.fmt.fmtSliceHexUpper(
        &aes_gcm_tag,
    ) });

    try std.testing.expect(std.mem.eql(u8, plain_text, decrypted_text));

    const pks_1 = try allocator.alloc(
        u8,
        buf_key_2.len * 2 + aes_gcm_tag.len * 2 + nonce_2.len * 2 + aad_text.len * 2 + sep_size_bytes,
    );

    defer allocator.free(pks_1);

    try sobocrypto_pks.makePortableKeySuite(
        pks_1,
        buf_key_2,
        &aes_gcm_tag,
        nonce_2,
        aad_text,
        sep_size_bytes,
    );

    var pks_struct = sobocrypto_pks.PortableKeySuite.init(
        buf_key_2,
        &aes_gcm_tag,
        nonce_2,
        aad_text,
    );

    // const pks_2 = try allocator.alloc(u8, buf_key_2.len * 2 + aes_gcm_tag.len * 2 + nonce_2.len * 2 + aad_text.len * 2 + sep_size_bytes);

    const size_pks_2 = sobocrypto_pks.PortableKeySuite.getHexStringKeySizeConst();
    const pks_2 = try allocator.alloc(u8, size_pks_2);
    defer allocator.free(pks_2);

    try pks_struct.getHexString(pks_2);

    std.debug.print("\n\nSIZE PKS: {} SIZE PKS_2: {}\n\n", .{ pks_1.len, size_pks_2 });
    std.debug.print("\n\nCONTENT PKS: {s}\nCONTENT PKS_2: {s}\n\n", .{ pks_1, pks_2 });

    try std.testing.expectEqual(pks_1.len, size_pks_2);
    try std.testing.expectEqual(pks_2.len, size_pks_2);

    std.debug.print("\nPortable Key Suite: {s}\n", .{pks_1});
    std.debug.print("\nPortable Key Suite FROM STRUCT: {s}\n", .{pks_2});

    try std.testing.expect(std.mem.eql(u8, pks_1, pks_2));

    try std.testing.expectStringStartsWith(pks_1, "W");
    try std.testing.expectStringEndsWith(pks_1, "W");

    try std.testing.expectStringStartsWith(pks_2, "W");
    try std.testing.expectStringEndsWith(pks_2, "W");

    var pks_struct_from_hex = try sobocrypto_pks.PortableKeySuite.initFromHexString(pks_2);

    // _ = pks_struct_from_hex;

    const size_pks_from_hex = sobocrypto_pks.PortableKeySuite.getHexStringKeySizeConst();
    try std.testing.expectEqual(pks_1.len, size_pks_from_hex);

    const pks_from_hex = try allocator.alloc(u8, size_pks_from_hex);
    defer allocator.free(pks_from_hex);

    try pks_struct_from_hex.getHexString(pks_from_hex);

    try std.testing.expect(std.mem.eql(u8, pks_from_hex, pks_1));
    try std.testing.expect(std.mem.eql(u8, pks_from_hex, pks_2));
}
