const std = @import("std");
const sockaddr = std.c.sockaddr;
const socklen_t = std.c.socklen_t;
const AF = std.posix.AF;

const pcap_if = struct {
    next: ?*pcap_if,
    name: [*:0]const u8, // name to hand to "pcap_open_live()"
    description: ?[*:0]const u8, // textual description of interface, or NULL
    addresses: ?*pcap_addr,
    flags: c_uint, // PCAP_IF_ interface flags
};

const pcap_addr = struct {
    next: ?*pcap_addr,
    addr: ?*sockaddr, // address
    netmask: ?*sockaddr, // netmask for that address
    broadaddr: ?*sockaddr, // broadcast address for that address
    dstaddr: ?*sockaddr, // P2P destination address for that address
};

const PCAP_IF_LOOPBACK: c_uint = 0x00000001; // interface is loopback
const PCAP_IF_UP: c_uint = 0x00000002; // interface is up
const PCAP_IF_RUNNING: c_uint = 0x00000004; // interface is running
const PCAP_IF_WIRELESS: c_uint = 0x00000008; // interface is wireless (*NOT* necessarily Wi-Fi!)
const PCAP_IF_CONNECTION_STATUS: c_uint = 0x00000030; // connection status:
const PCAP_IF_CONNECTION_STATUS_UNKNOWN: c_uint = 0x00000000; // unknown
const PCAP_IF_CONNECTION_STATUS_CONNECTED: c_uint = 0x00000010; // connected
const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: c_uint = 0x00000020; // disconnected
const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: c_uint = 0x00000030; // not applicable

const PCAP_ERRBUF_SIZE = 256;
const PCAP_CHAR_ENC_UTF_8: c_uint = 0x1;
extern fn pcap_init(opts: c_uint, errbuf: [*:0]const u8) callconv(.C) c_int;
extern fn pcap_statustostr(errnum: c_int) callconv(.C) [*:0]const u8;
extern fn pcap_findalldevs(alldevsp: *?*pcap_if, errbuf: [*:0]const u8) callconv(.C) c_int;
extern fn pcap_freealldevs(alldevs: ?*pcap_if) callconv(.C) void;

// defined in arpa/inet.h of libc:
extern fn inet_ntop(af: c_int, src: *anyopaque, dst: [*]u8, size: socklen_t) callconv(.C) ?[*:0]const u8;

fn write_sockaddr(writer: std.io.AnyWriter, addr: *sockaddr) !void {
    // POXIS defines INET_ADDRSTRLEN to 16 and INET6_ADDRSTRLEN to 46
    // https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/netinet_in.h.html
    var buf: [64:0]u8 = undefined;
    const result = switch (addr.family) {
        AF.INET => blk: {
            const addr_v4: *sockaddr.in = @alignCast(@ptrCast(addr));
            break :blk inet_ntop(AF.INET, &addr_v4.addr, &buf, buf.len);
        },
        AF.INET6 => blk: {
            const addr_v6: *sockaddr.in6 = @alignCast(@ptrCast(addr));
            break :blk inet_ntop(AF.INET6, &addr_v6.addr, &buf, buf.len);
        },
        else => |af| (try std.fmt.bufPrintZ(&buf, "unsupported address family: {d}", .{af})).ptr,
    };

    if (result == null) {
        const err: std.posix.E = @enumFromInt(std.c._errno().*);
        return std.posix.unexpectedErrno(err);
    }
    try writer.writeAll(std.mem.sliceTo(&buf, 0));
}

fn list_network_devices(writer: std.io.AnyWriter, tty_config: std.io.tty.Config, alldevs: *pcap_if) !void {
    try writer.writeAll("Available network interfaces:\n");
    var current_dev: ?*pcap_if = alldevs;
    while (current_dev) |dev| : (current_dev = dev.next) {
        try writer.print("  - {s} ", .{dev.name});
        try tty_config.setColor(writer, .dim);
        try writer.writeByte('(');

        var needs_comma = false;
        if ((dev.flags & PCAP_IF_LOOPBACK) > 0) {
            try tty_config.setColor(writer, .yellow);
            try writer.writeAll("loopback");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if ((dev.flags & PCAP_IF_UP) > 0) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .cyan);
            try writer.writeAll("up");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if ((dev.flags & PCAP_IF_RUNNING) > 0) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .blue);
            try writer.writeAll("running");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if ((dev.flags & PCAP_IF_WIRELESS) > 0) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .magenta);
            try writer.writeAll("wireless");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        switch (dev.flags & PCAP_IF_CONNECTION_STATUS) {
            PCAP_IF_CONNECTION_STATUS_UNKNOWN => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .yellow);
                try writer.writeAll("unknown status");
            },
            PCAP_IF_CONNECTION_STATUS_CONNECTED => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .green);
                try writer.writeAll("connected");
            },
            PCAP_IF_CONNECTION_STATUS_DISCONNECTED => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .red);
                try writer.writeAll("disconnected");
            },
            PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE => {},
            else => unreachable,
        }
        try tty_config.setColor(writer, .reset);
        try tty_config.setColor(writer, .dim);

        try writer.writeByte(')');
        try tty_config.setColor(writer, .reset);
        try writer.writeByte('\n');

        if (dev.description) |descr| {
            try writer.print("    description: {s}\n", .{descr});
        }

        if (dev.addresses) |addresses| {
            try writer.writeAll("    addresses: \n");
            const indent = "        ";

            var current_dev_addr: ?*pcap_addr = addresses;
            while (current_dev_addr) |dev_addr| : (current_dev_addr = dev_addr.next) {
                try writer.writeAll("      - ");
                var write_indent = false;

                if (dev_addr.addr) |addr| {
                    if (write_indent) try writer.writeAll(indent);
                    try writer.writeAll("address: ");
                    try write_sockaddr(writer, addr);
                    try writer.writeByte('\n');
                    write_indent = true;
                }
                if (dev_addr.netmask) |netmask| {
                    if (write_indent) try writer.writeAll(indent);
                    try writer.writeAll("netmask: ");
                    try write_sockaddr(writer, netmask);
                    try writer.writeByte('\n');
                    write_indent = true;
                }
                if (dev_addr.broadaddr) |broadaddr| {
                    if (write_indent) try writer.writeAll(indent);
                    try writer.writeAll("broadaddr: ");
                    try write_sockaddr(writer, broadaddr);
                    try writer.writeByte('\n');
                    write_indent = true;
                }
                if (dev_addr.dstaddr) |dstaddr| {
                    if (write_indent) try writer.writeAll(indent);
                    try writer.writeAll("dstaddr: ");
                    try write_sockaddr(writer, dstaddr);
                    try writer.writeByte('\n');
                    write_indent = true;
                }
            }
        }
    }
}

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();

    const tty_config = std.io.tty.detectConfig(std.io.getStdOut());
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var errbuf: [PCAP_ERRBUF_SIZE:0]u8 = undefined;
    const init_rc = pcap_init(PCAP_CHAR_ENC_UTF_8, &errbuf);
    if (init_rc != 0) {
        stderr.print("Failed to initialize libpcap: {s}\n", .{pcap_statustostr(init_rc)}) catch {};
        std.process.exit(1);
    }

    var alldevs: ?*pcap_if = null;
    const fad_rc = pcap_findalldevs(&alldevs, &errbuf);
    if (fad_rc != 0) {
        stderr.print("Can't list network devices: {s}\n", .{pcap_statustostr(fad_rc)}) catch {};
        std.process.exit(1);
    }
    defer pcap_freealldevs(alldevs);

    if (alldevs) |a| try list_network_devices(stdout.any(), tty_config, a);

    try bw.flush();
}
