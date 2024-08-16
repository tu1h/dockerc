const common = @import("common.zig");
const std = @import("std");
const assert = std.debug.assert;

pub fn main() !void {
    var args = std.process.args();
    assert(args.skip());

    if (args.next()) |dockercGeneratedBinary| {
        if (args.next()) |squashfsOutput| {
            const offset = (try common.getFooter(dockercGeneratedBinary)).offset;

            const readFile = try std.fs.cwd().openFile(dockercGeneratedBinary, .{});
            const writeFile = try std.fs.cwd().createFile(squashfsOutput, .{});

            // try writeFile.writeAll(runtimes.runtime_content_x86_64);
            const len_to_write = try readFile.getEndPos() - offset - 8;
            assert(try writeFile.getPos() == 0);
            const len_written = try std.fs.File.copyRange(readFile, offset, writeFile, 0, len_to_write);
            assert(len_to_write == len_written);

            writeFile.close();
            readFile.close();
        }
    }
}
