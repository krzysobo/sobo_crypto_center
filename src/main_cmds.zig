// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const pks = @import("sobocrypto_aes_pks.zig");
const sobocrypto_common = @import("sobocrypto_common.zig");
const sobocrypto_aes = @import("sobocrypto_aes.zig");
const sobocrypto_dh = @import("sobocrypto_dh.zig");
const hexed = @import("hexed.zig");
const DhKeyPair = std.crypto.dh.X25519.KeyPair;

pub fn encryptAesGcm(plaintext: []u8) !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n... Starting AES-GCM encryption of text:\n'{s}'\n...\n", .{plaintext});

    const res = try sobocrypto_aes.aesGcmWholeEncryptProcess(plaintext, allocator);

    const enc_data_hex = try sobocrypto_aes.convertAesEncryptedDataToHex(res.aes_enc_data, allocator);
    const key_hex = try sobocrypto_aes.convertAesKeyToHex(&res.aes_key, allocator);
    defer allocator.free(enc_data_hex);
    defer allocator.free(key_hex);

    std.debug.print("ENCRYPTED DATA:\n{s}\nAES KEY:\n{s}\n\n", .{ enc_data_hex, key_hex });
}

pub fn decryptAesGcm(ciphertext_hex: []u8, hex_key: []u8) !void {
    const allocator = std.heap.page_allocator;
    // _ = allocator;

    // _ = ciphertext_hex;
    // _ = hex_key;
    std.debug.print("\n... Starting decryption of ciphertext:\n'{s}'\nwith hex_key:\n'{s}'\n...\n", .{ ciphertext_hex, hex_key });

    const aes_enc_data = try sobocrypto_aes.convertHexToAesEncryptedData(ciphertext_hex, allocator);

    const aes_key = try hexed.hexToBytesAlloc(hex_key, allocator);
    defer allocator.free(aes_key);
    // _ = aes_enc_data;

    const plaintext = try sobocrypto_aes.aesGcmDecryptFromStruct(
        aes_enc_data,
        aes_key,
        allocator,
    );

    std.debug.print("Decrypted text:\n{s}\n\n========================================\n", .{plaintext});
}

pub fn generateDhKeyPair() !void { // TODO
    // const allocator = std.heap.page_allocator;
    std.debug.print("\n... Generating Diffie-Hellman's key pair...\n\n", .{});
    const kp = try sobocrypto_dh.makeKeyPair();
    std.debug.print("\nKEY PAIR:\n~~~~~~~~~~\nSECRET_KEY:\n{s}\nPUBLIC_KEY:\n{s}\n\n\n", .{ std.fmt.fmtSliceHexUpper(&kp.secret_key), std.fmt.fmtSliceHexUpper(&kp.public_key) });
}

pub fn generateDhPublicKey(dh_priv_key_hex: []u8) !void {
    const allocator = std.heap.page_allocator;
    std.debug.print("\n... Generating Diffie-Hellman's public key from private key '{s}'... - \n\n\n", .{dh_priv_key_hex});

    const dh_priv_key_bytes = try hexed.hexToBytesAlloc(dh_priv_key_hex, allocator);
    defer allocator.free(dh_priv_key_bytes);

    const pub_key_bytes = try sobocrypto_dh.makePublicKey(
        dh_priv_key_bytes[0..sobocrypto_dh.SizesDh.dh_private_key].*,
    );

    std.debug.print("PUBLIC KEY:\n{s}\n\n", .{std.fmt.fmtSliceHexUpper(&pub_key_bytes)});
}

pub fn encryptDhGenerateOurPublicKey(
    plaintext: []u8,
    their_dh_pub_key_hex: []u8,
    our_dh_priv_key_hex: []u8,
) !void { // TODO
    // std.debug.print("\n... Encrypting a plaintext '{s}' with Diffie-Hellman's public key '{s}' and generating our public key... - TODO\n\n", .{ plaintext, their_dh_pub_key_hex });
    const allocator = std.heap.page_allocator;
    const our_dh_priv_key_bytes: []u8 = try hexed.hexToBytesAlloc(
        our_dh_priv_key_hex,
        allocator,
    );
    defer allocator.free(our_dh_priv_key_bytes);
    _ = try hexed.hexToBytes(our_dh_priv_key_bytes, our_dh_priv_key_hex);

    const our_generated_pub_key = try sobocrypto_dh.makePublicKey(our_dh_priv_key_bytes[0..32].*);
    const our_generated_pub_key_hex = try hexed.bytesToHexAlloc(our_generated_pub_key, std.fmt.Case.upper, allocator);

    defer allocator.free(our_generated_pub_key_hex);
    // std.debug.print("\n==== OUR GENERATED PUB KEY:\n{s}\n", .{std.fmt.fmtSliceHexUpper(&our_generated_pub_key)});
    return encryptDh(
        plaintext,
        their_dh_pub_key_hex,
        our_dh_priv_key_hex,
        our_generated_pub_key_hex,
    );
}

pub fn encryptDh(
    plaintext: []u8,
    their_dh_pub_key_hex: []u8,
    our_dh_priv_key_hex: []u8,
    our_dh_pub_key_hex: []u8,
) !void { // TODO
    const allocator = std.heap.page_allocator;
    std.debug.print("\n... Encrypting a plaintext '{s}' with Diffie-Hellman's public key '{s}'...\n\n", .{ plaintext, their_dh_pub_key_hex });
    // _ = dh_pub_key_hex;
    // _ = plaintext;

    const our_dh_priv_key_bytes: []u8 = try allocator.alloc(u8, sobocrypto_dh.SizesDh.dh_private_key);
    const our_dh_pub_key_bytes: []u8 = try allocator.alloc(u8, sobocrypto_dh.SizesDh.dh_public_key);
    const their_dh_pub_key_bytes: []u8 = try allocator.alloc(u8, sobocrypto_dh.SizesDh.dh_public_key);
    defer allocator.free(our_dh_priv_key_bytes);
    defer allocator.free(our_dh_pub_key_bytes);
    defer allocator.free(their_dh_pub_key_bytes);

    _ = try hexed.hexToBytes(our_dh_priv_key_bytes, our_dh_priv_key_hex);
    _ = try hexed.hexToBytes(our_dh_pub_key_bytes, our_dh_pub_key_hex);
    _ = try hexed.hexToBytes(their_dh_pub_key_bytes, their_dh_pub_key_hex);

    std.debug.print("\n==== OUR PRIV KEY:\n{s}\n", .{our_dh_priv_key_hex});
    std.debug.print("\n==== OUR PUB KEY:\n{s}\n", .{our_dh_pub_key_hex});
    std.debug.print("\n==== THEIR PUB KEY:\n{s}\n", .{their_dh_pub_key_hex});

    var enc_data: sobocrypto_dh.EncryptedData = try sobocrypto_dh.encryptDh(
        plaintext,
        our_dh_pub_key_bytes[0..sobocrypto_dh.SizesDh.dh_public_key].*,
        our_dh_priv_key_bytes[0..sobocrypto_dh.SizesDh.dh_private_key].*,
        their_dh_pub_key_bytes[0..sobocrypto_dh.SizesDh.dh_public_key].*,
        allocator,
    );

    const res = try enc_data.getHex(allocator, false);
    std.debug.print("\n==== ENCRYPTED DATA:\n{s}\n\n\n", .{res});

    defer allocator.free(res);
}

// for decryption of a hex ciphertext
pub fn decryptDhCiphertextHex(ciphertext_hex: []u8, dh_priv_key_hex: []u8) !void { // TODO
    const allocator = std.heap.page_allocator;

    std.debug.print("\n... Un-hexing and decrypting a ciphertext hex:\n{s}\n" ++
        "\n...with Diffie-Hellman's private key\n{s}\n\n", .{
        ciphertext_hex,
        dh_priv_key_hex,
    });

    const enc_data: sobocrypto_dh.EncryptedData = try sobocrypto_dh.EncryptedData.initFromHexString(
        ciphertext_hex,
        allocator,
    );

    const priv_key_bytes = try hexed.hexToBytesAlloc(dh_priv_key_hex, allocator);
    defer allocator.free(priv_key_bytes);

    const dec_data = try sobocrypto_dh.decryptDh(
        enc_data,
        priv_key_bytes[0..sobocrypto_dh.SizesDh.dh_private_key].*,
        allocator,
    );

    std.debug.print("\nDECRYPTED MESSAGE:\n{s}\n\n", .{dec_data});
}

pub fn generateRaKeyPair() !void { // TODO
    std.debug.print("\n... Generating RSA-AES Hybrid key pair... - TODO\n\n", .{});
}

pub fn generateRaPublicKey(ra_priv_key_hex: []u8) !void { // TODO
    std.debug.print("\n... Generating RSA-AES Hybrid's public key from private key '{s}'... - TODO\n\n", .{ra_priv_key_hex});
    // _ = ra_priv_key_hex;
}

pub fn encryptRa(plaintext: []u8, ra_pub_key_hex: []u8) !void { // TODO
    std.debug.print("\n... Encrypting a plaintext '{s}' with RSA-AES Hybrid's public key '{s}'... - TODO\n\n", .{ plaintext, ra_pub_key_hex });
    // _ = plaintext;
    // _ = ra_pub_key_hex;
}

pub fn decryptRaCiphertextHex(ciphertext_hex: []u8, ra_priv_key_hex: []u8) !void { // TODO
    std.debug.print("\n... Un-hexing and decrypting a ciphertext hex '{s}' with RSA-AES Hybrid's private key '{s}'... - TODO\n\n", .{ ciphertext_hex, ra_priv_key_hex });
    // _ = ciphertext_hex;
    // _ = ra_priv_key_hex;
}

pub fn debugArgs(cli_args: [][:0]u8) !void {
    std.debug.print("There are {d} args:\n", .{cli_args.len});
    for (cli_args) |arg| {
        std.debug.print("  {s}\n", .{arg});
    }
}
