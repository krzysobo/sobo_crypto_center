// Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
// Repo location: https://github.com/krzysobo/sobo_crypto_center/
// License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE


const std = @import("std");
const sobocrypto_aes = @import("sobocrypto_aes.zig");
const hexed = @import("hexed.zig");
const cli = @import("main_cli.zig");
const cmds = @import("main_cmds.zig");


pub fn main() !void {
    // read parameters 
    var gen_purpose_alloc = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator_0 = gen_purpose_alloc.allocator();
    defer _ = gen_purpose_alloc.deinit();

    try cli.process(allocator_0);
}


