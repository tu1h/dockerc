const runtimes = @import("runtimes.zig");
const assert = std.debug.assert;
const std = @import("std");
const common = @import("common.zig");

pub fn main() !void {
    var args = std.process.args();
    assert(args.skip());
    const rawPath = args.next();
    const rawPathOutput = args.next();

    if (rawPath) |path| {
        if (rawPathOutput) |path_output| {
            const offset = (try common.getFooter(path)).offset;

            const readFile = try std.fs.cwd().openFile(path, .{});
            const writeFile = try std.fs.cwd().createFile(path_output, .{});

            try writeFile.writeAll(runtimes.runtime_content_x86_64);
            const len_to_write = try readFile.getEndPos() - offset - 8;
            const len_written = try std.fs.File.copyRange(readFile, offset, writeFile, try writeFile.getPos(), len_to_write);
            assert(len_to_write == len_written);

            try writeFile.seekFromEnd(0);

            try common.writeFooter(writeFile, common.Footer{
                .offset = runtimes.runtime_content_x86_64.len,
            });

            try writeFile.chmod(0o755);

            writeFile.close();
            readFile.close();
        }
    }
}
