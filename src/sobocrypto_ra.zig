// // Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// // Repo location: https://github.com/krzysobo/sobo_crypto_center/
// // License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

// // ------ imports and shortcuts ------
// const std = @import("std");
// const hexed = @import("hexed.zig");
// const common = @import("sobocrypto_common.zig");
// const sobocrypto_aes = @import("sobocrypto_aes.zig");
// const makeSalt = common.basic_crypto_randoms.array_based.makeSalt;
// const makeNonce = common.basic_crypto_randoms.array_based.makeNonce;
// const X25519 = std.crypto.dh.X25519;
// // const rsa = std.crypto
// const DhKeyPair = X25519.KeyPair;

// // ------ structs and other data definitions -------
// pub const SizesRa = struct {
//     // AES-GCM
//     pub const aes_key: comptime_int = 32;
//     pub const aes_tag: comptime_int = 16;
//     pub const nonce: comptime_int = 12;
//     pub const salt: comptime_int = 32;

//     // RSA
//     pub const rsa_public_key: comptime_int = 256; // 256 bytes = 2048 bits
//     pub const rsa_private_key: comptime_int = 256; // 256 bytes = 2048 bits
//     pub const rsa_private_exponent: comptime_int = 256; // 256 bytes = 2048 bits
//     pub const rsa_public_exponent: comptime_int = 3;
// };

// pub const EncryptedData = struct {
//     salt: [SizesRa.salt]u8,
//     nonce: [SizesRa.nonce]u8,
//     ciphertext: []u8,
//     our_public_key: [SizesRa.dh_public_key]u8,
//     our_next_public_key: [SizesDh.dh_public_key]u8,
//     tag: [SizesAesGcm.aes_tag]u8,

//     pub fn getHex(
//         self: *EncryptedData,
//         allocator: std.mem.Allocator,
//         add_next_public_key: bool,
//     ) ![]u8 {
//         var xargs = std.ArrayList(u8).init(allocator);

//         const cipher_hex = try hexed.bytesToHexAlloc(self.ciphertext, std.fmt.Case.upper, allocator);
//         const tag_hex = try hexed.bytesToHexAlloc(self.tag, std.fmt.Case.upper, allocator);
//         const salt_hex = try hexed.bytesToHexAlloc(self.salt, std.fmt.Case.upper, allocator);
//         const nonce_hex = try hexed.bytesToHexAlloc(self.nonce, std.fmt.Case.upper, allocator);
//         const our_public_key_hex = try hexed.bytesToHexAlloc(self.our_public_key, std.fmt.Case.upper, allocator);

//         defer allocator.free(cipher_hex);
//         defer allocator.free(tag_hex);
//         defer allocator.free(salt_hex);
//         defer allocator.free(nonce_hex);
//         defer allocator.free(our_public_key_hex);

//         try xargs.append('W');
//         try xargs.appendSlice(cipher_hex);
//         try xargs.append('H');
//         try xargs.appendSlice(tag_hex);
//         try xargs.append('H');
//         try xargs.appendSlice(salt_hex);
//         try xargs.append('H');
//         try xargs.appendSlice(nonce_hex);
//         try xargs.append('H');
//         try xargs.appendSlice(our_public_key_hex);

//         if (add_next_public_key) {
//             try xargs.append('H');
//             try xargs.appendSlice(self.our_next_public_key ++ "DUPA");
//         }
//         try xargs.append('W');

//         // std.debug.print("\nXARGS ITEMS : {s}", .{xargs.items});
//         const res = xargs.toOwnedSlice();
//         return res;
//     }

//     pub fn initFromHexString(buf_hex: []const u8, allocator: std.mem.Allocator) !EncryptedData {
//         if (!std.mem.startsWith(u8, buf_hex, "W") or
//             !std.mem.endsWith(u8, buf_hex, "W"))
//         {
//             return error.InvalidEncryptedDataHexFormat;
//         }

//         const buf_hex_trimmed = std.mem.trim(u8, buf_hex, "W");
//         if (buf_hex_trimmed.len != buf_hex.len - 2) {
//             return error.InvalidEncryptedDataHexFormat;
//         }

//         var xargs = std.ArrayList([]u8).init(allocator);
//         var it = std.mem.splitScalar(u8, buf_hex_trimmed, 'H');
//         const it_first_bytes = try hexed.hexToBytesAlloc(it.first(), allocator);

//         try xargs.append(it_first_bytes);

//         var i: u8 = 0;
//         while (it.next()) |val| {
//             const it_bytes = try hexed.hexToBytesAlloc(val, allocator);
//             try xargs.append(it_bytes);
//             i += 1;
//         }

//         if ((xargs.items.len != 5) and (xargs.items.len != 6)) {
//             return error.InvalidDhEncryptedDataHexFormat;
//         }

//         // W + cipher_hex + H + tag_hex + H + salt_hex + H + nonce_hex + H + our_pub_key_hex + W [OR]
//         // W + cipher_hex + H + tag_hex + H + salt_hex + H + nonce_hex + H + our_pub_key_hex + H + our_next_pub_key + W
//         const res: EncryptedData = .{
//             .ciphertext = xargs.items[0][0..xargs.items[0].len],
//             .tag = xargs.items[1][0..SizesAesGcm.aes_tag].*,
//             .salt = xargs.items[2][0..SizesAesGcm.salt].*,
//             .nonce = xargs.items[3][0..SizesAesGcm.nonce].*,
//             .our_public_key = xargs.items[4][0..SizesDh.dh_public_key].*,
//             .our_next_public_key = if (xargs.items.len == 6)
//                 xargs.items[5][0..SizesDh.dh_public_key].*
//             else
//                 undefined,
//         };

//         xargs.clearAndFree();
//         xargs.deinit();

//         return res;
//     }
// };

// // ------ public functions -------
// pub fn encryptRsaAes(
//     plaintext: []u8,
//     our_public_key: [SizesDh.dh_public_key]u8,
//     our_secret_key: [SizesDh.dh_private_key]u8,
//     their_public_key: [SizesDh.dh_public_key]u8,
//     allocator: std.mem.Allocator,
// ) !EncryptedData {
//     const our_shs = try makeSharedSecret(our_secret_key, their_public_key);

//     const enc_data = encryptUsingSharedSecret(
//         plaintext,
//         our_shs,
//         our_public_key,
//         our_public_key,
//         allocator,
//     );

//     return enc_data;
// }

// fn encryptUsingAes(plaintext: []u8) |void {
//     const salt: [SizesAesGcm.salt]u8 = try makeSalt(SizesAesGcm.salt);
//     const nonce: [SizesAesGcm.nonce]u8 = try makeNonce(SizesAesGcm.nonce);
//     const output_ciphertext = try allocator.alloc(u8, plaintext.len);
//     var output_aes_gcm_tag: [16]u8 = undefined;

//     // _ = shared_secret;
//     const aes_key = try makeAesKeyFromSharedSecret(shared_secret, salt);

//     // std.debug.print("\n=== ENCRYPT - AES KEY: '{s}'\n\n", .{std.fmt.fmtSliceHexUpper(&aes_key)});
//     // std.debug.print("\n=== ENCRYPT - SHARED SECRET: '{s}'\n\n", .{std.fmt.fmtSliceHexUpper(&shared_secret)});

//     try sobocrypto_aes.aesGcmEncrypt(
//         output_ciphertext,
//         &output_aes_gcm_tag,
//         plaintext,
//         &aes_key,
//         &nonce,
//         "alfa beta gamma",
//         SizesAesGcm.nonce,
//         SizesAesGcm.aes_key,
//     );

//     return .{
//         .salt = salt,
//         .nonce = nonce,
//         .ciphertext = output_ciphertext,
//         .our_public_key = our_public_key,
//         .our_next_public_key = our_next_public_key,
//         .tag = output_aes_gcm_tag,
//     };

// }

// // pub fn decryptRsaAes(
// //     enc_data: EncryptedData,
// //     our_secret_key: [SizesRa.rsa_private_key]u8,
// //     allocator: std.mem.Allocator,
// // ) ![]u8 {
// //     const our_shs = try makeSharedSecret(
// //         our_secret_key,
// //         enc_data.our_public_key,
// //     );

// //     const dec_data = try decryptUsingSharedSecret(
// //         enc_data,
// //         our_shs,
// //         allocator,
// //     );

// //     return dec_data;
// // }

// // pub fn makeRsaKeyPair() !DhKeyPair {
// //     const kp = DhKeyPair.generate();
// //     return kp;
// // }

// // ============================== tests ====================================
// // TODO
