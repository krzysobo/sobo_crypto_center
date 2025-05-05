const std = @import("std");
const sobocrypto_aes = @import("sobocrypto_aes.zig");
const hexed = @import("hexed.zig");


fn show_basic_info() !void {
    std.debug.print(
        "\n=========================================================================================================" ++
        "\n  Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo" ++
        "\n  Repo location: https://github.com/krzysobo/sobo_crypto_center/" ++
        "\n  License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE" ++
        "\n=========================================================================================================\n\n", .{});

}


fn show_correct_syntax() !void {
    std.debug.print(
        "The correct syntax is:\n  ./sobocrypto_center [enc \"plaintext\"]|[dec \"ciphertext\" \"hexkeysuite\"]\n\n" ++
            "  [enc \"plaintext\"] for encryption with AES-GCM\n" ++
            "  [dec \"ciphertext\" \"hexkeysuite\"] for decryption with AES-GCM\n\n", .{});
}


fn encrypt(plain_text: []u8) !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n... Starting encryption of text:\n'{s}'\n...\n", .{plain_text});

    const encrypted_text: []u8 = try allocator.alloc(u8, plain_text.len * 2);
    const buf_portable_key_hex: []u8 = try allocator.alloc(u8, sobocrypto_aes.PortableKeySuite.getHexStringKeySizeConst());

    try sobocrypto_aes.aesGcmEncryptToHex(encrypted_text, buf_portable_key_hex, plain_text);

    defer allocator.free(encrypted_text);
    defer allocator.free(buf_portable_key_hex);
    std.debug.print("ENCRYPTED TEXT:\n{s}\nPortable Key Suite:\n{s}\n\n", .{encrypted_text, buf_portable_key_hex});
}


fn decrypt(ciphertext_hex: []u8, hex_key_suite: []u8) !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n... Starting decryption of ciphertext:\n'{s}'\nwith hex_key_suite:\n'{s}'\n...\n", .{
        ciphertext_hex, hex_key_suite});

    const decrypted_text = try allocator.alloc(u8, ciphertext_hex.len / 2);
    try sobocrypto_aes.aesGcmDecryptFromHex(decrypted_text, ciphertext_hex, hex_key_suite);

    defer allocator.free(decrypted_text);
    std.debug.print("Decrypted text:\n{s}\n\n========================================\n", .{decrypted_text});
}


fn debug_args(cli_args: [][:0]u8) !void {
    std.debug.print("There are {d} args:\n", .{cli_args.len});
    for(cli_args) |arg| {
        std.debug.print("  {s}\n", .{arg});
    }
}


pub fn main() !void {
    std.debug.print("\nHello World in Sobo-Crypto-Center.\n\n", .{});


    // read parameters 
    var gen_purpose_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator_0 = gen_purpose_alloc.allocator();
    defer _ = gen_purpose_alloc.deinit();

    const cli_args = try std.process.argsAlloc(allocator_0);
    defer std.process.argsFree(allocator_0, cli_args);

    try debug_args(cli_args);
    try show_basic_info();

    if (cli_args.len < 3) {
        try show_correct_syntax();
        return;
    } else if ((cli_args.len == 3) and (std.mem.eql(u8, cli_args[1], "enc"))) {
        try encrypt(cli_args[2]);
        return;
    } else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "dec"))) {
        try decrypt(cli_args[2], cli_args[3]);
        return;
    } else {
        try show_correct_syntax();
        return;
    }


 
}


