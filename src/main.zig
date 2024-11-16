const std = @import("std");
const mem = std.mem;
const log = std.log;
const sockaddr = std.c.sockaddr;
const socklen_t = std.c.socklen_t;
const timeval = std.c.timeval;
const AF = std.posix.AF;

const pcap_t = opaque {};

const pcap_if = extern struct {
    next: ?*pcap_if,
    name: [*:0]const u8, // name to hand to "pcap_open_live()"
    description: ?[*:0]const u8, // textual description of interface, or NULL
    addresses: ?*pcap_addr,
    flags: c_uint, // PCAP_IF_ interface flags
};

const pcap_addr = extern struct {
    next: ?*pcap_addr,
    addr: ?*sockaddr, // address
    netmask: ?*sockaddr, // netmask for that address
    broadaddr: ?*sockaddr, // broadcast address for that address
    dstaddr: ?*sockaddr, // P2P destination address for that address
};

const pcap_pkthdr = extern struct {
    ts: timeval, // time stamp
    caplen: c_uint, // length of portion present in data
    len: c_uint, // length of this packet prior to any slicing
};

const TstampPrecision = enum(c_int) {
    Micro = 0,
    Nano = 1,

    fn from_str(name: []const u8) ?TstampPrecision {
        const map = std.StaticStringMap(TstampPrecision).initComptime(.{
            .{ "micro", .Micro },
            .{ "nano", .Nano },
        });
        return map.get(name);
    }
};

const pcap_handler = *const fn (user: ?*c_char, header: *const pcap_pkthdr, packet: *const c_char) callconv(.C) void;

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

const PCAP_TSTAMP_ADAPTER: c_int = 3;
extern fn pcap_create(device: [*:0]const u8, errbuf: [*:0]const u8) callconv(.C) ?*pcap_t;
extern fn pcap_activate(p: *pcap_t) callconv(.C) c_int;
extern fn pcap_set_snaplen(p: *pcap_t, snaplen: c_int) callconv(.C) c_int;
extern fn pcap_set_promisc(p: *pcap_t, promisc: c_int) callconv(.C) c_int;
extern fn pcap_set_immediate_mode(p: *pcap_t, immediate: c_int) callconv(.C) c_int;
extern fn pcap_set_buffer_size(p: *pcap_t, buffer_size: c_int) callconv(.C) c_int;
extern fn pcap_set_timeout(p: *pcap_t, timeout_ms: c_int) callconv(.C) c_int;
extern fn pcap_set_tstamp_type(p: *pcap_t, tstamp_type: c_int) callconv(.C) c_int;
extern fn pcap_tstamp_type_name_to_val(name: [*:0]const u8) callconv(.C) c_int;
extern fn pcap_set_tstamp_precision(p: *pcap_t, tstamp_precision: c_int) callconv(.C) c_int;
extern fn pcap_dispatch(p: *pcap_t, cnt: c_int, callback: pcap_handler, user: ?*c_char) callconv(.C) c_int;

// defined in arpa/inet.h of libc:
extern fn inet_ntop(af: c_int, src: *anyopaque, dst: [*]u8, size: socklen_t) callconv(.C) ?[*:0]const u8;

// header and packet pointers are invalid after this callback returns
fn capture_callback(user: ?*c_char, header: *const pcap_pkthdr, packet: *const c_char) callconv(.C) void {
    _ = user;
    _ = header;
    _ = packet;
    std.debug.print("hi\n", .{});
}

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

const help_text =
    \\Capture network traffic using libpcap and publish it via MQTT.
    \\By default the hostname is used as client ID and all packets are
    \\captured from the first available network interface.
    \\
    \\If PCAP file file is supplied, the packets are replayed instead of
    \\capturing live traffic from the network interface.
    \\
    \\Usage: pcap_publisher [OPTIONS]
    \\
    \\General Options:
    \\      --client-id <VALUE>  Unique identifier for this client
    \\      --uri <VALUE>        URI of MQTT broker [default: tcp://localhost:1883]
    \\      --prefix <VALUE>     Prefix of MQTT topic [default: ]
    \\  -f, --file <PATH>        Path to .pcap file for replay
    \\      --username <VALUE>   Username for MQTT broker (MQTT_USERNAME env variable)
    \\      --password <VALUE>   Password for MQTT broker (MQTT_PASSWORD env variable)
    \\  -h, --help               Print help
    \\  -V, --version            Print version
    \\
    \\Capture Options:
    \\  -d, --dev <DEVICE>         Name of captured network interface
    \\      --ts-type <ENUM>       Location where timestamp is recorded
    \\          'host' -> Host adds timestamp rather than capture device
    \\                    No commitment if timestamp will be low or high precision
    \\          'host_lowprec' -> Host, low precision
    \\          'host_hiprec' -> Host, high precision (Default)
    \\          'host_hiprec_unsynced' -> Host, high precision, not synced with system time
    \\          'adapter' -> Adapter, high precision, synced with system time
    \\          'adapter_unsynced' -> Adapter, high precision, not synced with system time
    \\      --ts-precision <ENUM>  Precision of network packet timestamps
    \\          'micro' -> microsecond precision
    \\          'nano' -> nanosecond precision (Default)
    \\
;

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();

    const tty_config = std.io.tty.detectConfig(std.io.getStdOut());
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    defer bw.flush() catch {};
    const stdout = bw.writer();

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var errbuf: [PCAP_ERRBUF_SIZE:0]u8 = undefined;
    const init_rc = pcap_init(PCAP_CHAR_ENC_UTF_8, &errbuf);
    if (init_rc != 0) {
        stderr.print("Failed to initialize libpcap: {s}\n", .{pcap_statustostr(init_rc)}) catch {};
        std.process.exit(1);
    }

    var verbose_level: u32 = 0;
    var capture_dev: ?[:0]const u8 = null;
    var pcap_file: ?[:0]const u8 = null;
    var broker_uri: ?[:0]const u8 = null;
    var client_id: ?[:0]const u8 = null;
    var prefix: ?[:0]const u8 = null;
    var username: ?[:0]const u8 = null;
    var password: ?[:0]const u8 = null;
    var timestamp_type: c_int = PCAP_TSTAMP_ADAPTER;
    var timestamp_precision: TstampPrecision = .Nano;

    _ = args.skip(); // first argument is executable path
    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            // Bypass the buffered writer for stdout, because we will call exit()
            try stdout_file.writeAll(help_text);
            std.process.exit(1);
        } else if (mem.eql(u8, "-V", arg) or mem.eql(u8, "--version", arg)) {
            try stdout.print("pcap_publisher {s}\n", .{"0.2"});
            return;
        } else if (mem.eql(u8, "-v", arg) or mem.eql(u8, "--verbose", arg)) {
            verbose_level += 1;
        } else if (mem.eql(u8, "-d", arg) or mem.eql(u8, "--dev", arg)) {
            capture_dev = args.next() orelse {
                stderr.print("Missing argument for --dev\n", .{}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "-f", arg) or mem.eql(u8, "--file", arg)) {
            pcap_file = args.next() orelse {
                stderr.print("Missing argument for --file\n", .{}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--uri", arg)) {
            broker_uri = args.next() orelse {
                stderr.print("Missing argument for --uri\n", .{}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--client-id", arg)) {
            client_id = args.next() orelse {
                stderr.print("Missing argument for --client-id\n", .{}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "-p", arg) or mem.eql(u8, "--prefix", arg)) {
            prefix = args.next() orelse {
                stderr.print("Missing argument for --prefix\n", .{}) catch {};
                std.process.exit(1);
            };
            if (prefix.?.len == 0 or prefix.?[prefix.?.len - 1] != '/') {
                stderr.print("MQTT topic prefix must end with `/`: {s}\n", .{prefix.?}) catch {};
                std.process.exit(1);
            }
        } else if (mem.eql(u8, "--ts-type", arg)) {
            const raw_ts_type = args.next() orelse {
                stderr.print("Missing argument for --ts-type\n", .{}) catch {};
                std.process.exit(1);
            };
            const ts_to_val_rc = pcap_tstamp_type_name_to_val(raw_ts_type.ptr);
            if (ts_to_val_rc == -1) {
                stderr.print("Invalid timestamp type: {s}\n", .{raw_ts_type}) catch {};
                std.process.exit(1);
            }
            timestamp_type = ts_to_val_rc;
        } else if (mem.eql(u8, "--ts-precision", arg)) {
            const raw_ts_precision = args.next() orelse {
                stderr.print("Missing argument for --ts-precision\n", .{}) catch {};
                std.process.exit(1);
            };
            timestamp_precision = TstampPrecision.from_str(raw_ts_precision) orelse {
                stderr.print("Invalid timestamp precision: {s}\n", .{raw_ts_precision}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--username", arg)) {
            username = args.next() orelse {
                stderr.print("Missing argument for --username\n", .{}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--password", arg)) {
            password = args.next() orelse {
                stderr.print("Missing argument for --password\n", .{}) catch {};
                std.process.exit(1);
            };
        } else {
            stderr.print("Invalid argument: {s}\n", .{arg}) catch {};
            std.process.exit(1);
        }
    }

    if (capture_dev != null and pcap_file != null) {
        stderr.writeAll("Choose between capturing live traffic with --dev and " ++
            "replaying a PCAP with --file\n") catch {};
        std.process.exit(1);
    }

    if (capture_dev) |dev| {
        const handle = pcap_create(dev, &errbuf) orelse {
            stderr.print("Failed to create capture device for '{s}': {s}\n", .{ dev, errbuf }) catch {};
            std.process.exit(1);
        };

        // The calls to change settings only fail if `pcap_activate` was already called.
        // Because of this we omit the error handling here. If a device i.e. does not
        // support promiscuous mode, the activate call will raise an error.
        // Immediate mode is needed because the packets should be sent directly via
        // MQTT without delay instead of batching them.
        _ = pcap_set_promisc(handle, 1);
        _ = pcap_set_immediate_mode(handle, 1);
        _ = pcap_set_snaplen(handle, 65535);
        _ = pcap_set_buffer_size(handle, 64 << 20); // 64MB
        _ = pcap_set_timeout(handle, 100); // 100ms

        // Check if capture device supports requested timestamp type and precision
        const ts_type_rc = pcap_set_tstamp_type(handle, timestamp_type);
        if (ts_type_rc != 0) {
            stderr.print("Failed to set timestamp type: {s}\n", .{pcap_statustostr(ts_type_rc)}) catch {};
            std.process.exit(1);
        }
        const ts_prec_rc = pcap_set_tstamp_precision(handle, @intFromEnum(timestamp_precision));
        if (ts_prec_rc != 0) {
            stderr.print("Failed to set timestamp precision: {s}\n", .{pcap_statustostr(ts_prec_rc)}) catch {};
            std.process.exit(1);
        }

        const activate_rc = pcap_activate(handle);
        if (activate_rc != 0) {
            stderr.print("Failed to start capture: {s}\n", .{pcap_statustostr(activate_rc)}) catch {};
            std.process.exit(1);
        }

        while (true) {
            // Dispatch will return either if the callback was triggered 50 times or the timeout was reached
            const dispatch_rc = pcap_dispatch(handle, 50, capture_callback, null);
            if (dispatch_rc != 0) {
                log.warn("Could not run capture callback: {s}\n", .{pcap_statustostr(dispatch_rc)});
                continue;
            }
        }
    } else if (pcap_file) |pcap| {
        _ = pcap; // TODO replay file
    } else {
        var alldevs: ?*pcap_if = null;
        const fad_rc = pcap_findalldevs(&alldevs, &errbuf);
        if (fad_rc != 0) {
            stderr.print("Can't list network devices: {s}\n", .{pcap_statustostr(fad_rc)}) catch {};
            std.process.exit(1);
        }
        defer pcap_freealldevs(alldevs);

        if (alldevs) |a| {
            try list_network_devices(stdout.any(), tty_config, a);
            try stdout.writeAll("\nChoose a network interface and run the program " ++
                "again with --dev <name> to capture live traffic\n");
        } else {
            stderr.writeAll("Did not find any network interfaces\n") catch {};
        }
    }
}
