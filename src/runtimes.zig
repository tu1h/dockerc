const std = @import("std");

pub const runtime_content_x86_64 = @embedFile("runtime_x86_64");
pub const runtime_content_aarch64 = @embedFile("runtime_aarch64");
