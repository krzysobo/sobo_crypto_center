// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

// ------ imports and shortcuts ------
const std = @import("std");
const hexed = @import("hexed.zig");
const common = @import("sobocrypto_common.zig");
const sobocrypto_aes = @import("sobocrypto_aes.zig");
const makeSalt = common.basic_crypto_randoms.array_based.makeSalt;
const makeNonce = common.basic_crypto_randoms.array_based.makeNonce;
const X25519 = std.crypto.dh.X25519;
const DhKeyPair = X25519.KeyPair;

// ------ structs and other data definitions -------
pub const SizesDh = struct {
    pub const aes_key: comptime_int = 32;
    pub const nonce: comptime_int = 12;
    pub const salt: comptime_int = 32;
    pub const dh_public_key: comptime_int = X25519.public_length;
    pub const dh_private_key: comptime_int = X25519.secret_length;
    pub const dh_shared_secret: comptime_int = X25519.shared_length;
    pub const dh_tag: comptime_int = 16;
};

const AesKeyData = struct {
    salt: [SizesDh.salt]u8,
    nonce: [SizesDh.nonce]u8,
    aes_key: [SizesDh.aes_key]u8,
};

pub const EncryptedData = struct {
    salt: [SizesDh.salt]u8,
    nonce: [SizesDh.nonce]u8,
    ciphertext: []u8,
    our_public_key: [SizesDh.dh_public_key]u8,
    our_next_public_key: [SizesDh.dh_public_key]u8,
    tag: [SizesDh.dh_tag]u8,

    pub fn getHex(
        self: *EncryptedData,
        allocator: std.mem.Allocator,
        add_next_public_key: bool,
    ) ![]u8 {
        var xargs = std.ArrayList(u8).init(allocator);

        const cipher_hex = try hexed.bytesToHexAlloc(self.ciphertext, std.fmt.Case.upper, allocator);
        const tag_hex = try hexed.bytesToHexAlloc(self.tag, std.fmt.Case.upper, allocator);
        const salt_hex = try hexed.bytesToHexAlloc(self.salt, std.fmt.Case.upper, allocator);
        const nonce_hex = try hexed.bytesToHexAlloc(self.nonce, std.fmt.Case.upper, allocator);
        const our_public_key_hex = try hexed.bytesToHexAlloc(self.our_public_key, std.fmt.Case.upper, allocator);

        defer allocator.free(cipher_hex);
        defer allocator.free(tag_hex);
        defer allocator.free(salt_hex);
        defer allocator.free(nonce_hex);
        defer allocator.free(our_public_key_hex);

        try xargs.append('W');
        try xargs.appendSlice(cipher_hex);
        try xargs.append('H');
        try xargs.appendSlice(tag_hex);
        try xargs.append('H');
        try xargs.appendSlice(salt_hex);
        try xargs.append('H');
        try xargs.appendSlice(nonce_hex);
        try xargs.append('H');
        try xargs.appendSlice(our_public_key_hex);

        if (add_next_public_key) {
            try xargs.append('H');
            try xargs.appendSlice(self.our_next_public_key ++ "DUPA");
        }
        try xargs.append('W');

        // std.debug.print("\nXARGS ITEMS : {s}", .{xargs.items});
        const res = xargs.toOwnedSlice();
        return res;
    }

    pub fn initFromHexString(buf_hex: []const u8, allocator: std.mem.Allocator) !EncryptedData {
        if (!std.mem.startsWith(u8, buf_hex, "W") or
            !std.mem.endsWith(u8, buf_hex, "W"))
        {
            return error.InvalidEncryptedDataHexFormat;
        }

        const buf_hex_trimmed = std.mem.trim(u8, buf_hex, "W");
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

        if ((xargs.items.len != 5) and (xargs.items.len != 6)) {
            return error.InvalidDhEncryptedDataHexFormat;
        }

        // W + cipher_hex + H + tag_hex + H + salt_hex + H + nonce_hex + H + our_pub_key_hex + W [OR]
        // W + cipher_hex + H + tag_hex + H + salt_hex + H + nonce_hex + H + our_pub_key_hex + H + our_next_pub_key + W
        const res: EncryptedData = .{
            .ciphertext = xargs.items[0][0..xargs.items[0].len],
            .tag = xargs.items[1][0..SizesDh.dh_tag].*,
            .salt = xargs.items[2][0..SizesDh.salt].*,
            .nonce = xargs.items[3][0..SizesDh.nonce].*,
            .our_public_key = xargs.items[4][0..SizesDh.dh_public_key].*,
            .our_next_public_key = if (xargs.items.len == 6)
                xargs.items[5][0..SizesDh.dh_public_key].*
            else
                undefined,
        };

        xargs.clearAndFree();
        xargs.deinit();

        return res;
    }
};

// ------ public functions -------
pub fn encryptDh(
    plaintext: []u8,
    our_public_key: [SizesDh.dh_public_key]u8,
    our_secret_key: [SizesDh.dh_private_key]u8,
    their_public_key: [SizesDh.dh_public_key]u8,
    allocator: std.mem.Allocator,
) !EncryptedData {
    const our_shs = try makeSharedSecret(our_secret_key, their_public_key);

    const enc_data = encryptUsingSharedSecret(
        plaintext,
        our_shs,
        our_public_key,
        our_public_key,
        allocator,
    );

    return enc_data;
}

pub fn decryptDh(
    enc_data: EncryptedData,
    our_secret_key: [SizesDh.dh_private_key]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const our_shs = try makeSharedSecret(
        our_secret_key,
        enc_data.our_public_key,
    );

    const dec_data = try decryptUsingSharedSecret(
        enc_data,
        our_shs,
        allocator,
    );

    return dec_data;
}

pub fn encryptUsingSharedSecret(
    plaintext: []u8,
    shared_secret: [SizesDh.dh_shared_secret]u8,
    our_public_key: [SizesDh.dh_public_key]u8,
    our_next_public_key: [SizesDh.dh_public_key]u8,
    allocator: std.mem.Allocator,
) !EncryptedData {
    const salt: [SizesDh.salt]u8 = try makeSalt(SizesDh.salt);
    const nonce: [SizesDh.nonce]u8 = try makeNonce(SizesDh.nonce);
    const output_ciphertext = try allocator.alloc(u8, plaintext.len);
    var output_aes_gcm_tag: [16]u8 = undefined;

    // _ = shared_secret;
    const aes_key = try makeAesKeyFromSharedSecret(shared_secret, salt);

    // std.debug.print("\n=== ENCRYPT - AES KEY: '{s}'\n\n", .{std.fmt.fmtSliceHexUpper(&aes_key)});
    // std.debug.print("\n=== ENCRYPT - SHARED SECRET: '{s}'\n\n", .{std.fmt.fmtSliceHexUpper(&shared_secret)});

    try sobocrypto_aes.aesGcmEncrypt(
        output_ciphertext,
        &output_aes_gcm_tag,
        plaintext,
        &aes_key,
        &nonce,
        "alfa beta gamma",
        SizesDh.nonce,
        SizesDh.aes_key,
    );

    return .{
        .salt = salt,
        .nonce = nonce,
        .ciphertext = output_ciphertext,
        .our_public_key = our_public_key,
        .our_next_public_key = our_next_public_key,
        .tag = output_aes_gcm_tag,
    };
}

pub fn decryptUsingSharedSecret(
    enc_data: EncryptedData,
    shared_secret: [SizesDh.dh_shared_secret]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const aes_key = try makeAesKeyFromSharedSecret(shared_secret, enc_data.salt);
    const output_plain_text: []u8 = try allocator.alloc(u8, enc_data.ciphertext.len);
    try sobocrypto_aes.aesGcmDecrypt(
        output_plain_text,
        enc_data.ciphertext,
        &aes_key,
        enc_data.tag,
        &enc_data.nonce,
        "alfa beta gamma",
        SizesDh.nonce,
        SizesDh.aes_key,
    );

    return output_plain_text;
}

pub fn makeKeyPair() !DhKeyPair {
    const kp = DhKeyPair.generate();
    return kp;
}

pub fn makePublicKey(secret_key: [SizesDh.dh_private_key]u8) ![SizesDh.dh_public_key]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(secret_key);
}

pub fn makeSharedSecret(
    my_private_key: [X25519.secret_length]u8,
    their_public_key: [SizesDh.dh_public_key]u8,
) ![SizesDh.dh_shared_secret]u8 {
    const shared_secret = std.crypto.dh.X25519.scalarmult(my_private_key, their_public_key);
    return shared_secret;
}

pub fn makeAesKeyFromSharedSecret(
    shared_secret: [X25519.shared_length]u8,
    salt: [SizesDh.salt]u8,
) ![SizesDh.aes_key]u8 {
    var aes_key: [SizesDh.aes_key]u8 = undefined;
    const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    // hkdf.expand(&aes_key, &shared_secret, "blah-blah-blah-blah");
    const prk: [hkdf.prk_length]u8 = hkdf.extract(&salt, &shared_secret);
    hkdf.expand(&aes_key, "hybrid-encryption", prk);

    return aes_key;
}

// ============================== tests ====================================

test "our and their shared keys are identical" {
    std.debug.print("\n... Generating Diffie-Hellman's key pair for 'us' and for 'them'... - TODO\n\n", .{});
    const kp = try makeKeyPair();
    const th = try makeKeyPair();
    std.debug.print("\nOUR KEY PAIR:\nSECRET_KEY:\n{s}\nPUBLIC_KEY:\n{s}\n\n", .{ std.fmt.fmtSliceHexUpper(&kp.secret_key), std.fmt.fmtSliceHexUpper(&kp.public_key) });
    std.debug.print("\nTHEIR KEY PAIR:\nSECRET_KEY:\n{s}\nPUBLIC_KEY:\n{s}\n\n", .{ std.fmt.fmtSliceHexUpper(&th.secret_key), std.fmt.fmtSliceHexUpper(&th.public_key) });
    const our_shs = try makeSharedSecret(kp.secret_key, th.public_key);
    const their_shs = try makeSharedSecret(th.secret_key, kp.public_key);

    std.debug.print("\n OUR SHARED SECRET: {s}\n\n", .{std.fmt.fmtSliceHexUpper(&our_shs)});
    std.debug.print("\n THEIR SHARED SECRET: {s}\n\n", .{std.fmt.fmtSliceHexUpper(&their_shs)});

    try std.testing.expect(std.mem.eql(u8, &our_shs, &their_shs));

    const allocator = std.heap.page_allocator;
    const plaintext = try allocator.alloc(u8, 10);
    _ = try std.fmt.bufPrint(plaintext, "1234567890", .{});

    const enc_data: EncryptedData = try encryptUsingSharedSecret(
        plaintext,
        our_shs,
        kp.public_key,
        kp.public_key,
        allocator,
    );

    defer allocator.free(plaintext);
    defer allocator.free(enc_data.ciphertext);
    std.debug.print("\n\nCIPHER: {s}\nSALT: {s}\nNONCE: {s}\nTAG: {s}\n" ++
        "OUR PUB KEY: {s}\nOUR NEXT PUB KEY: {s}\n\n ", .{
        std.fmt.fmtSliceHexUpper(enc_data.ciphertext),
        std.fmt.fmtSliceHexUpper(&enc_data.salt),
        std.fmt.fmtSliceHexUpper(&enc_data.nonce),
        std.fmt.fmtSliceHexUpper(&enc_data.tag),
        std.fmt.fmtSliceHexUpper(&enc_data.our_public_key),
        std.fmt.fmtSliceHexUpper(&enc_data.our_next_public_key),
    });
}

// pub fn makePrivateKey(out_buf: []u8) !void{
//     const allocator = std.heap.page_allocator;
// const sender_public_key = std.crypto.dh.X25519.publicKey(sender_private_key);
// }
