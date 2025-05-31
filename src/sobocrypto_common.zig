const std = @import("std");
const hexed = @import("hexed.zig");

pub const basic_crypto_randoms = struct {
    pub const slice_based = struct {
        pub fn makeRandomKey(key_buf: []u8, comptime key_length_bytes: comptime_int) !void {
            if (key_buf.len != key_length_bytes) {
                return error.InvalidSize;
            }
            std.crypto.random.bytes(key_buf);
        }

        pub fn makeNonce(output_nonce: []u8, nonce_size: comptime_int) !void {
            return slice_based.makeRandomKey(output_nonce, nonce_size);
        }

        pub fn makeSalt(output_salt: []u8, nonce_size: comptime_int) !void {
            return slice_based.makeRandomKey(output_salt, nonce_size);
        }
    };

    pub const array_based = struct {
        pub fn makeRandomKey(comptime key_length_bytes: comptime_int) ![key_length_bytes]u8 {
            var key_data: [key_length_bytes]u8 = undefined;
            std.crypto.random.bytes(&key_data);
            return key_data;
        }

        pub fn makeNonce(comptime key_length_bytes: comptime_int) ![key_length_bytes]u8 {
            return array_based.makeRandomKey(key_length_bytes);
        }

        pub fn makeSalt(comptime key_length_bytes: comptime_int) ![key_length_bytes]u8 {
            return array_based.makeRandomKey(key_length_bytes);
        }
    };
};
