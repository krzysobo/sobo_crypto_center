// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const hexed = @import("hexed.zig");
const common = @import("sobocrypto_common.zig");
const sobocrypto_pks = @import("sobocrypto_aes_pks.zig");
const makeRandomKey = common.basic_crypto_randoms.slice_based.makeRandomKey;
const makeNonce = common.basic_crypto_randoms.slice_based.makeNonce;
const makeSalt = common.basic_crypto_randoms.array_based.makeSalt;
const default_aad_text = "alfa beta gamma";

// ------ public constants and structs -------
pub const SizesAesGcm = struct {
    // AES-GCM
    pub const aes_key: comptime_int = 32;
    pub const aes_tag: comptime_int = 16;
    pub const nonce: comptime_int = 12;
    pub const salt: comptime_int = 32;
};

pub const AesEncryptedData = struct {
    salt: [SizesAesGcm.salt]u8,
    nonce: [SizesAesGcm.nonce]u8,
    ciphertext: []u8,
    tag: [SizesAesGcm.aes_tag]u8,
    aad_text: []const u8,
};

pub const AesEncryptedDataAndKey = struct {
    aes_key: [SizesAesGcm.aes_key]u8,
    aes_enc_data: AesEncryptedData,
};

pub fn convertAesKeyToHex(aes_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const key_hex = try hexed.bytesToHexAlloc(aes_key, std.fmt.Case.upper, allocator);
    return key_hex;
}

// ------ public functions -------
pub fn convertAesEncryptedDataToHex(
    aes_enc_data: AesEncryptedData,
    allocator: std.mem.Allocator,
) ![]u8 {
    var xargs = std.ArrayList(u8).init(allocator);

    // AES-GCM
    const cipher_hex = try hexed.bytesToHexAlloc(aes_enc_data.ciphertext, std.fmt.Case.upper, allocator);
    const tag_hex = try hexed.bytesToHexAlloc(aes_enc_data.tag, std.fmt.Case.upper, allocator);
    const aad_text_hex = try hexed.bytesToHexAlloc(aes_enc_data.aad_text, std.fmt.Case.upper, allocator);
    const salt_hex = try hexed.bytesToHexAlloc(aes_enc_data.salt, std.fmt.Case.upper, allocator);
    const nonce_hex = try hexed.bytesToHexAlloc(aes_enc_data.nonce, std.fmt.Case.upper, allocator);

    defer allocator.free(cipher_hex);
    defer allocator.free(tag_hex);
    defer allocator.free(aad_text_hex);
    defer allocator.free(salt_hex);
    defer allocator.free(nonce_hex);

    // S + cipher_hex + H + tag_hex + H + aad_text_hex + H + salt_hex + H + nonce_hex + S
    try xargs.append('S');
    try xargs.appendSlice(cipher_hex);
    try xargs.append('H');
    try xargs.appendSlice(tag_hex);
    try xargs.append('H');
    try xargs.appendSlice(aad_text_hex);
    try xargs.append('H');
    try xargs.appendSlice(salt_hex);
    try xargs.append('H');
    try xargs.appendSlice(nonce_hex);
    try xargs.append('S');

    // std.debug.print("\nXARGS ITEMS : {s}", .{xargs.items});
    const res = xargs.toOwnedSlice();
    return res;
}

pub fn convertHexToAesEncryptedData(buf_hex: []const u8, allocator: std.mem.Allocator) !AesEncryptedData {
    if (!std.mem.startsWith(u8, buf_hex, "S") or
        !std.mem.endsWith(u8, buf_hex, "S"))
    {
        return error.InvalidEncryptedDataHexFormat;
    }

    const buf_hex_trimmed = std.mem.trim(u8, buf_hex, "S");
    if (buf_hex_trimmed.len != buf_hex.len - 2) {
        return error.InvalidEncryptedDataHexFormat;
    }

    var xargs = std.ArrayList([]u8).init(allocator);
    var it = std.mem.splitScalar(u8, buf_hex_trimmed, 'H');
    const it_first_bytes = try hexed.hexToBytesAlloc(it.first(), allocator);

    try xargs.append(it_first_bytes);

    var i: u8 = 0;
    while (it.next()) |val| {
        const it_bytes = try hexed.hexToBytesAlloc(val, allocator);
        try xargs.append(it_bytes);
        i += 1;
    }

    if (xargs.items.len != 5) {
        return error.InvalidAesEncryptedDataHexFormat;
    }

    // S + cipher_hex + H + tag_hex + H + aad_text + H + salt_hex + H + nonce_hex + S
    const res: AesEncryptedData = .{
        // AES-GCM
        .ciphertext = xargs.items[0][0..xargs.items[0].len],
        .tag = xargs.items[1][0..SizesAesGcm.aes_tag].*,
        .aad_text = xargs.items[2],
        .salt = xargs.items[3][0..SizesAesGcm.salt].*,
        .nonce = xargs.items[4][0..SizesAesGcm.nonce].*,
    };

    xargs.clearAndFree();
    xargs.deinit();

    return res;
}

pub fn aesGcmWholeEncryptProcess(
    input_plaintext: []const u8,
    allocator: std.mem.Allocator,
) !AesEncryptedDataAndKey {
    const salt: [SizesAesGcm.salt]u8 = try makeSalt(SizesAesGcm.salt);
    const nonce: [SizesAesGcm.nonce]u8 = try common.basic_crypto_randoms.array_based.makeNonce(SizesAesGcm.nonce);
    const aes_key: [SizesAesGcm.aes_key]u8 = try common.basic_crypto_randoms.array_based.makeRandomKey(SizesAesGcm.aes_key);
    const aad_text = default_aad_text;

    const aes_enc_data = try aesGcmEncryptToStruct(
        input_plaintext,
        aes_key,
        nonce,
        aad_text,
        salt,
        allocator,
    );

    return .{
        .aes_enc_data = aes_enc_data,
        .aes_key = aes_key,
    };
}

pub fn aesGcmEncryptToStruct(
    input_plaintext: []const u8,
    aes_key: [SizesAesGcm.aes_key]u8,
    nonce: [SizesAesGcm.nonce]u8,
    aad_text: []const u8,
    salt: [SizesAesGcm.salt]u8,
    allocator: std.mem.Allocator,
) !AesEncryptedData {
    const output_ciphertext: []u8 = try allocator.alloc(u8, input_plaintext.len);
    var output_aes_gcm_tag: [SizesAesGcm.aes_tag]u8 = undefined; // GCM tag

    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        output_ciphertext,
        &output_aes_gcm_tag,
        input_plaintext,
        aad_text,
        nonce,
        aes_key,
    );

    return .{
        .salt = salt,
        .nonce = nonce,
        .ciphertext = output_ciphertext,
        .tag = output_aes_gcm_tag,
        .aad_text = aad_text,
    };
}

pub fn aesGcmDecryptFromStruct(aes_enc_data: AesEncryptedData, aes_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const output_plain_text = try allocator.alloc(u8, aes_enc_data.ciphertext.len);
    const aes_key_out: [SizesAesGcm.aes_key]u8 = aes_key[0..SizesAesGcm.aes_key].*;

    try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        output_plain_text,
        aes_enc_data.ciphertext,
        aes_enc_data.tag,
        aes_enc_data.aad_text,
        aes_enc_data.nonce,
        aes_key_out,
    );

    return output_plain_text;
}

pub fn aesGcmDecrypt(
    output_plain_text: []u8,
    input_ciphertext: []const u8,
    input_cipher_key: []const u8,
    input_aes_gcm_tag: [16]u8,
    input_nonce: []const u8,
    aad_text: []const u8,
) !void {
    const nonce_out: [SizesAesGcm.nonce]u8 = input_nonce[0..SizesAesGcm.nonce].*;
    const cipher_key_out: [SizesAesGcm.aes_key]u8 = input_cipher_key[0..SizesAesGcm.aes_key].*;

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

pub fn aesGcmEncrypt(
    output_ciphertext: []u8,
    output_aes_gcm_tag: *[16]u8,
    input_plaintext: []const u8,
    cipher_key: []const u8,
    nonce: []const u8,
    aad_text: []const u8,
) !void {
    if (cipher_key.len != SizesAesGcm.aes_key) return error.InvalidKeyLength;
    if (nonce.len != SizesAesGcm.nonce) return error.InvalidNonceLength;
    if (output_ciphertext.len != input_plaintext.len) return error.InvalidCiphertextLength;

    var nonce_out: [SizesAesGcm.nonce]u8 = nonce[0..SizesAesGcm.nonce].*;
    var cipher_key_out: [SizesAesGcm.aes_key]u8 = cipher_key[0..SizesAesGcm.aes_key].*;

    if (!std.mem.eql(u8, nonce, &nonce_out)) return error.InvalidNonceCopy;
    if (!std.mem.eql(u8, cipher_key, &cipher_key_out)) return error.InvalidCipherKeyCopy;

    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
        output_ciphertext,
        output_aes_gcm_tag,
        input_plaintext,
        aad_text,
        nonce_out,
        cipher_key_out,
    );
}

pub fn aesGcmDecryptFromHex(
    decrypted_text: []u8,
    ciphertext_hex: []u8,
    hex_key_suite: []u8,
) !void {
    if (ciphertext_hex.len % 2 != 0) {
        return error.InvalidCiphertextLength;
    }

    const allocator = std.heap.page_allocator;
    const ciphertext_bytes = try allocator.alloc(u8, ciphertext_hex.len / 2);
    _ = try hexed.hexToBytes(ciphertext_bytes, ciphertext_hex);

    const pks_struct = try sobocrypto_pks.PortableKeySuite.initFromHexString(hex_key_suite);
    const tag_buf_out: [16]u8 = pks_struct.tag_buf_in[0..16].*;

    return aesGcmDecrypt(decrypted_text, ciphertext_bytes, pks_struct.key_buf_in, tag_buf_out, pks_struct.nonce_buf_in, pks_struct.aad_buf_in);
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
    ));

    try std.testing.expectError(error.InvalidCiphertextLength, aesGcmEncrypt(
        encrypted_text,
        &aes_gcm_tag,
        plain_text_error,
        buf_key_2,
        nonce_2,
        aad_text,
    ));

    try aesGcmDecrypt(
        decrypted_text,
        encrypted_text,
        buf_key_2,
        aes_gcm_tag,
        nonce_2,
        aad_text,
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
