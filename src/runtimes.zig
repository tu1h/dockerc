const std = @import("std");

fn get_runtime_content_len_u64(runtime_content: []const u8) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, runtime_content.len, .big);
    return buf;
}

pub const runtime_content_x86_64 = @embedFile("runtime_x86_64");
pub const runtime_content_aarch64 = @embedFile("runtime_aarch64");

pub const runtime_content_len_u64_x86_64 = get_runtime_content_len_u64(runtime_content_x86_64);
pub const runtime_content_len_u64_aarch64 = get_runtime_content_len_u64(runtime_content_aarch64);
