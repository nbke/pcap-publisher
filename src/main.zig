const std = @import("std");

const PCAP_ERRBUF_SIZE = 256;
const PCAP_CHAR_ENC_UTF_8: c_uint = 0x1;
extern fn pcap_init(opts: c_uint, errbuf: [*:0]const u8) callconv(.C) c_int;
extern fn pcap_statustostr(errnum: c_int) callconv(.C) [*:0]const u8;

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();

    var errbuf: [PCAP_ERRBUF_SIZE:0]u8 = undefined;
    const init_rc = pcap_init(PCAP_CHAR_ENC_UTF_8, &errbuf);
    if (init_rc != 0) {
        stderr.print("Failed to initialize libpcap: {s}\n", .{pcap_statustostr(init_rc)}) catch {};
        std.process.exit(1);
    }

    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
}
