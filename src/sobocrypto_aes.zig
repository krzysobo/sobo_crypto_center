const std = @import("std");
const hexed = @import("hexed.zig");

const PortableKeySuite = struct {
    const sep_size_bytes : comptime_int= 5;    // 'W' + key + 'Q' + tag + 'Q' + nonce + 'Q' + aad + 'W'

    // port_buf_out: [] u8, 
    key_buf_in: []const u8,
    tag_buf_in: []const u8,
    nonce_buf_in: []const u8,
    aad_buf_in: []const u8,

    pub fn init(
        key_buf_in: []const u8,
        tag_buf_in: []const u8,
        nonce_buf_in: []const u8,
        aad_buf_in: []const u8
    ) PortableKeySuite {
        return PortableKeySuite{
            .key_buf_in   = key_buf_in,
            .tag_buf_in   = tag_buf_in,
            .nonce_buf_in = nonce_buf_in,
            .aad_buf_in   = aad_buf_in,
        };
    }

    pub fn getHexStringSize(self: PortableKeySuite) usize {
        return self.key_buf_in.len * 2 + 
            self.tag_buf_in.len * 2 + 
            self.nonce_buf_in.len * 2 + 
            self.aad_buf_in.len * 2 + 
            PortableKeySuite.sep_size_bytes;
    }

    // 'W' + key_buf_hex + 'Q' + tag_buf_hex + 'Q' + nonce_buf_hex + 'Q' + aad_buf_hex + 'W'
    pub fn getHexString(buf_out: []u8, self: PortableKeySuite) !void {
        return makePortableKeySuite(buf_out, 
            self.key_buf_in, 
            self.tag_buf_in, 
            self.nonce_buf_in, 
            self.aad_buf_in, 
            PortableKeySuite.sep_size_bytes);
    }

    // 'W' + key_buf_hex + 'Q' + tag_buf_hex + 'Q' + nonce_buf_hex + 'Q' + aad_buf_hex + 'W'
    pub fn initFromHexString(buf_hex_pks: []const u8) !PortableKeySuite {
        var key_buf_in : []u8 = undefined;
        var tag_buf_in : []u8 = undefined;
        var nonce_buf_in: []u8 = undefined;
        var aad_buf_in : []u8 = undefined;

        // std.debug.print("\n initFromHexString::: string::: {s}\n", .{buf_hex_pks});

        if (!std.mem.startsWith(u8, buf_hex_pks, "W") or !std.mem.startsWith(u8, buf_hex_pks, "W")) {
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
        while(it.next()) |val| {
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



pub fn aesGcmEncrypt(
        output_ciphertext: []u8, 
        output_aes_gcm_tag: *[16]u8, 
        input_plaintext: []const u8, 
        cipher_key: []const u8, 
        nonce: []const u8, 
        aad_text: []const u8, 
        nonce_size_bytes: comptime_int, 
        cipher_key_size_bytes: comptime_int) !void {
    

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
        input_nonce: []u8, 
        aad_text: []const u8, 
        nonce_size_bytes: comptime_int, 
        cipher_key_size_bytes: comptime_int) !void {

    const nonce_out: [nonce_size_bytes]u8 = input_nonce[0..nonce_size_bytes].*;
    const cipher_key_out: [cipher_key_size_bytes]u8 = input_cipher_key[0..cipher_key_size_bytes].*;

    return std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(output_plain_text, input_ciphertext, 
        input_aes_gcm_tag, aad_text, nonce_out, cipher_key_out);
}

// makes a random key and returns it via parameter
pub fn makeRandomKey(key_buf: []u8, comptime key_length_bytes: comptime_int) !void {
    if (key_buf.len != key_length_bytes) {
        return error.InvalidSize;
    }
    std.crypto.random.bytes(key_buf);
}

pub fn makeNonce(output_nonce: []u8, nonce_size: comptime_int) !void {
    return makeRandomKey(output_nonce, nonce_size);
}


pub fn makePortableKeySuite(
        port_buf_out: [] u8, 
        key_buf_in: []const u8, 
        tag_buf_in: []const u8, 
        nonce_buf_in: []const u8, 
        aad_buf_in: []const u8, sep_size_bytes: comptime_int) !void {

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

    const all_len = key_buf_hex.len + tag_buf_hex.len + nonce_buf_hex.len + aad_buf_hex.len + sep_size_bytes ;
    
    if (all_len != port_buf_out.len) return error.InvalidComponentsLength;

    _ = try std.fmt.bufPrint(port_buf_out, 
        "W{s}Q{s}Q{s}Q{s}W", 
        .{key_buf_hex, tag_buf_hex, nonce_buf_hex, aad_buf_hex});

    // std.debug.print("PKS: {s}\n--KEY BUF HEX: {s}\n--TAG BUF HEX: {s}\n--NONCE BUF HEX: {s}\n--AAD_BUF_HEX: {s}\n\n", 
    // .{port_buf_out, key_buf_hex, tag_buf_hex, nonce_buf_hex, aad_buf_hex});

}
// ======================================= tests =====================================

test makeRandomKey {
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

test makeNonce {
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
    const aad_text = "dolor sit amet...";
    var aes_gcm_tag: [16]u8 = undefined; // GCM tag

    const encrypted_text = try allocator.alloc(u8, plain_text.len);
    const decrypted_text = try allocator.alloc(u8, plain_text.len);

    defer allocator.free(encrypted_text);
    defer allocator.free(decrypted_text);
    defer allocator.free(nonce_2);
    defer allocator.free(buf_key_2);
    defer allocator.free(buf_key_2_hex);

    try aesGcmEncrypt(encrypted_text, &aes_gcm_tag, plain_text, buf_key_2, nonce_2, aad_text, nonce_size_bytes, key_size_bytes);

    const buf_key_3_error = try allocator.alloc(u8, key_size_bytes + 5);
    const plain_text_error = "Wrong length of text";
    
    try std.testing.expectError(error.InvalidKeyLength, aesGcmEncrypt(encrypted_text, &aes_gcm_tag, plain_text, buf_key_3_error, nonce_2, aad_text, nonce_size_bytes, key_size_bytes));

    try std.testing.expectError(error.InvalidCiphertextLength, aesGcmEncrypt(encrypted_text, &aes_gcm_tag, plain_text_error, buf_key_2, nonce_2, aad_text, nonce_size_bytes, key_size_bytes));

    try aesGcmDecrypt(decrypted_text, encrypted_text, buf_key_2, aes_gcm_tag, nonce_2, aad_text, nonce_size_bytes, key_size_bytes);
    std.debug.print("\n====> encrypted text: {any}\n--> ENC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{ encrypted_text, std.fmt.fmtSliceHexUpper(encrypted_text), aes_gcm_tag, std.fmt.fmtSliceHexUpper(&aes_gcm_tag) });
    std.debug.print("\n====> decrypted text: {s}\nANY: {any}\n--> DEC. TEXT HEX:{s}\nTAG: {any}\n-->TAG HASH: {s} \n\n", .{ decrypted_text, decrypted_text, std.fmt.fmtSliceHexUpper(decrypted_text), aes_gcm_tag, std.fmt.fmtSliceHexUpper(&aes_gcm_tag) });

    try std.testing.expect(std.mem.eql(u8, plain_text, decrypted_text));


    // makePortableKeySuite(port_buf_out: []u8, key_buf_in: []u8, tag_buf_in: []u8, nonce_buf_in: []u8, aad_buf_in: []u8)
    
    const pks = try allocator.alloc(u8, buf_key_2.len * 2 + aes_gcm_tag.len * 2 + nonce_2.len * 2 + aad_text.len * 2 + sep_size_bytes);


    defer allocator.free(pks);

    try makePortableKeySuite(pks, buf_key_2, &aes_gcm_tag, nonce_2, aad_text, sep_size_bytes);


    const pks_struct = PortableKeySuite.init(buf_key_2, &aes_gcm_tag, nonce_2, aad_text);

    // const pks_2 = try allocator.alloc(u8, buf_key_2.len * 2 + aes_gcm_tag.len * 2 + nonce_2.len * 2 + aad_text.len * 2 + sep_size_bytes);

    const size_pks_2 = PortableKeySuite.getHexStringSize(pks_struct);
    
    try std.testing.expectEqual(pks.len, size_pks_2);

    const pks_2 = try allocator.alloc(u8, size_pks_2);
    defer allocator.free(pks_2);

    try PortableKeySuite.getHexString(pks_2, pks_struct);

    std.debug.print("\nPortable Key Suite: {s}\n", .{pks});
    std.debug.print("\nPortable Key Suite FROM STRUCT: {s}\n", .{pks_2});

    try std.testing.expect(std.mem.eql(u8, pks, pks_2));

    try std.testing.expectStringStartsWith(pks, "W");
    try std.testing.expectStringEndsWith(pks,"W");

    try std.testing.expectStringStartsWith(pks_2, "W");
    try std.testing.expectStringEndsWith(pks_2,"W");

    const pks_struct_from_hex = try PortableKeySuite.initFromHexString(pks_2);

    // _ = pks_struct_from_hex;

    const size_pks_from_hex = PortableKeySuite.getHexStringSize(pks_struct_from_hex);
    try std.testing.expectEqual(pks.len, size_pks_from_hex);

    const pks_from_hex = try allocator.alloc(u8, size_pks_from_hex);
    defer allocator.free(pks_from_hex);

    try PortableKeySuite.getHexString(pks_from_hex, pks_struct_from_hex);

    try std.testing.expect(std.mem.eql(u8, pks_from_hex, pks));
    try std.testing.expect(std.mem.eql(u8, pks_from_hex, pks_2));

}

