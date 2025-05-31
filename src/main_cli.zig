// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE

const std = @import("std");
const sobocrypto_aes = @import("sobocrypto_aes.zig");

const hexed = @import("hexed.zig");
const cmds = @import("main_cmds.zig");
const version = "0.0.3";

fn showBasicInfo() !void {
    std.debug.print(
        \\=========================================================================================================
    ++ "\n                              *** Sobo Crypto Center v {s} ***                                      \n" ++
        \\  Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        \\  Repo location: https://github.com/krzysobo/sobo_crypto_center/
        \\  License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        \\=========================================================================================================
    , .{version});
}

fn showCorrectSyntax() !void {
    std.debug.print(
        \\
        \\ 
        \\ The correct syntax is:
        \\   ./sobocrypto_center ... positional options as below ...
        \\   [enc "plaintext"] for encryption with AES-GCM
        \\   [dec "ciphertext" "hexkeysuite"] for decryption with AES-GCM
        \\   -------------------
        \\   [dh_genkey] to generate a key pair for Diffie Hellman's (both in hex)
        \\   [dh_genpubkey "priv_key_hex"] to generate a public key for Diffie Hellman's from a private key hex
        \\   [dh_enc "plaintext" "their_pub_key_hex" "our_priv_key_hex" ["our_pub_key_hex"] ] to encrypt a plaintext with a public key hex (pub_key_src - public key hex.
        \\        -- the last parameter (our_pub_key_hex) is optional. If you don't provide it, the key will be regenerated from private key.
        // \\   [dh_dec "priv_key_hex" "ciphertext"] to decrypt a ciphertext (binary) with a public key (pub_key_src - public key hex
        \\   [dh_dec "ciphertext_hex" "our_priv_key_hex"] to decrypt a ciphertext (hex) with a public key (pub_key_src - public key hex
        \\   -------------------
        \\   [ra_genkey] to generate a key pair for RSA-AES (both in hex)
        \\   [ra_genpubkey "priv_key_hex"] to generate a public key for RSA-AES from a private key hex
        \\   [ra_enc "plaintext" "pub_key_hex"] to encrypt a plaintext with a public key hex (pub_key_src - public key hex
        // \\   [ra_dec "ciphertext" "priv_key_hex"] to decrypt a ciphertext (binary) with a public key (pub_key_src - public key hex
        \\   [ra_dechex "ciphertext" "priv_key_hex" ] to decrypt a ciphertext (hex) with a public key (pub_key_src - public key hex
        \\
        \\
    , .{});
}

fn debugArgs(cli_args: [][:0]u8) !void {
    std.debug.print("There are {d} args:\n", .{cli_args.len});
    for (cli_args) |arg| {
        std.debug.print("  {s}\n", .{arg});
    }
}

fn executeCommandsFromArgs(cli_args: [][:0]u8) !void {
    // AES-GCM: enc plaintext -> key + ciphertext
    if ((cli_args.len == 3) and (std.mem.eql(u8, cli_args[1], "enc"))) {
        try cmds.encryptAesGcm(cli_args[2]);
        return;
    }

    // AES-GCM: dec ciphertext keysuite -> plaintext
    else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "dec"))) {
        try cmds.decryptAesGcm(cli_args[2], cli_args[3]);
        return;
    }

    // ---------- Diffie Hellman's ----------
    //   [dh_genkey] to generate a key pair for Diffie Hellman's (both in hex)
    else if ((cli_args.len == 2) and (std.mem.eql(u8, cli_args[1], "dh_genkey"))) {
        try cmds.generateDhKeyPair();
    }

    //   [dh_genpubkey "priv_key_hex"] to generate a public key for Diffie Hellman's from a private key hex
    else if ((cli_args.len == 3) and (std.mem.eql(u8, cli_args[1], "dh_genpubkey"))) {
        try cmds.generateDhPublicKey(cli_args[2]);
    }

    //   [dh_enc "pub_key_hex" "plaintext"] to encrypt a plaintext with a public key hex (pub_key_src - public key hex
    else if ((cli_args.len == 6) and (std.mem.eql(u8, cli_args[1], "dh_enc"))) {
        try cmds.encryptDh(
            cli_args[2],
            cli_args[3],
            cli_args[4],
            cli_args[5],
        );
    } else if ((cli_args.len == 5) and (std.mem.eql(u8, cli_args[1], "dh_enc"))) {
        try cmds.encryptDhGenerateOurPublicKey(
            cli_args[2],
            cli_args[3],
            cli_args[4],
        );
    }

    // //   [dh_dec "priv_key_hex" "ciphertext"] to decrypt a ciphertext (binary) with a public key (pub_key_src - public key hex
    // else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "dh_dec"))) {
    //     try decryptDhCiphertext(cli_args[2], cli_args[3]);
    // }

    //   [dh_dec "ciphertext_hex" "priv_key_hex"] to decrypt a ciphertext (hex) with a public key (pub_key_src - public key hex
    else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "dh_dec"))) {
        try cmds.decryptDhCiphertextHex(cli_args[2], cli_args[3]);
    }
    // ---------- /Diffie Hellman's ----------

    // ---------- RSA-AES Hybrid ----------
    else if ((cli_args.len == 2) and (std.mem.eql(u8, cli_args[1], "ra_genkey"))) {
        try cmds.generateRaKeyPair();
    }

    //   [ra_genpubkey "priv_key_hex"] to generate a public key for RSA-AES from a private key hex
    else if ((cli_args.len == 3) and (std.mem.eql(u8, cli_args[1], "ra_genpubkey"))) {
        try cmds.generateRaPublicKey(cli_args[2]);
    }

    //   [dh_enc "plaintext" "pub_key_hex"] to encrypt a plaintext with a public key hex (pub_key_src - public key hex
    else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "ra_enc"))) {
        try cmds.encryptRa(cli_args[2], cli_args[3]);
    }

    // //   [dh_dec "ciphertext" "priv_key_hex" ] to decrypt a ciphertext (binary) with a public key (pub_key_src - public key hex
    // else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "ra_dec"))) {
    //     try decryptRaCiphertext(cli_args[2], cli_args[3]);
    // }

    //   [dh_dechex "ciphertext_hex" "priv_key_hex"] to decrypt a ciphertext (hex) with a public key (pub_key_src - public key hex
    else if ((cli_args.len == 4) and (std.mem.eql(u8, cli_args[1], "ra_dechex"))) {
        try cmds.decryptRaCiphertextHex(cli_args[2], cli_args[3]);
    }
    // ---------- /RSA-AES Hybrid ----------

    else {
        try showCorrectSyntax();
        return;
    }
}

pub fn process(allocator_0: std.mem.Allocator) !void {
    const cli_args = try std.process.argsAlloc(allocator_0);
    defer std.process.argsFree(allocator_0, cli_args);

    // try debugArgs(cli_args);
    try showBasicInfo();

    try executeCommandsFromArgs(cli_args);
}
