const std = @import("std");
const mem = std.mem;
const log = std.log;
const sockaddr = std.c.sockaddr;
const socklen_t = std.c.socklen_t;
const timeval = std.c.timeval;
const timespec = std.posix.timespec;
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

const TstampSource = enum(c_int) {
    host = 0,
    host_lowprec = 1,
    host_hiprec = 2,
    adapter = 3,
    adapter_unsynced = 4,
    host_hiprec_unsynced = 5,

    fn from_str(name: []const u8) ?TstampSource {
        const map = std.StaticStringMap(TstampSource).initComptime(.{
            .{ "host", .host },
            .{ "host_lowprec", .host_lowprec },
            .{ "host_hiprec", .host_hiprec },
            .{ "host_hiprec_unsynced", .host_hiprec_unsynced },
            .{ "adapter", .adapter },
            .{ "adapter_unsynced", .adapter_unsynced },
        });
        return map.get(name);
    }
};

const TstampPrecision = enum(c_int) {
    micro = 0,
    nano = 1,

    fn from_str(name: []const u8) ?TstampPrecision {
        const map = std.StaticStringMap(TstampPrecision).initComptime(.{
            .{ "micro", .micro },
            .{ "nano", .nano },
        });
        return map.get(name);
    }
};

const pcap_handler = *const fn (user: ?*c_char, header: *const pcap_pkthdr, packet: [*]const c_char) callconv(.C) void;

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

extern fn pcap_datalink(p: *pcap_t) callconv(.C) c_int;
extern fn pcap_list_datalinks(p: *pcap_t, dlt_buf: *[*]c_int) callconv(.C) c_int;
extern fn pcap_free_datalinks(dlt_list: [*]c_int) callconv(.C) void;
extern fn pcap_set_datalink(p: *pcap_t, dlt: c_int) callconv(.C) c_int;
extern fn pcap_datalink_val_to_name(dlt: c_int) callconv(.C) [*:0]const u8;
extern fn pcap_datalink_val_to_description(dlt: c_int) callconv(.C) [*:0]const u8;
extern fn pcap_datalink_name_to_val(name: [*:0]const u8) callconv(.C) c_int;

extern fn pcap_create(device: [*:0]const u8, errbuf: [*:0]const u8) callconv(.C) ?*pcap_t;
extern fn pcap_activate(p: *pcap_t) callconv(.C) c_int;
extern fn pcap_set_snaplen(p: *pcap_t, snaplen: c_int) callconv(.C) c_int;
extern fn pcap_set_promisc(p: *pcap_t, promisc: c_int) callconv(.C) c_int;
extern fn pcap_set_rfmon(p: *pcap_t, rfmon: c_int) callconv(.C) c_int;
extern fn pcap_set_immediate_mode(p: *pcap_t, immediate: c_int) callconv(.C) c_int;
extern fn pcap_set_buffer_size(p: *pcap_t, buffer_size: c_int) callconv(.C) c_int;
extern fn pcap_set_tstamp_type(p: *pcap_t, tstamp_type: c_int) callconv(.C) c_int;
extern fn pcap_set_tstamp_precision(p: *pcap_t, tstamp_precision: c_int) callconv(.C) c_int;
extern fn pcap_dispatch(p: *pcap_t, cnt: c_int, callback: pcap_handler, user: ?*c_char) callconv(.C) c_int;
extern fn pcap_get_tstamp_precision(p: *pcap_t) callconv(.C) c_int;
extern fn pcap_geterr(p: *pcap_t) callconv(.C) [*:0]const u8;

// defined in arpa/inet.h of libc:
extern fn inet_ntop(af: c_int, src: *anyopaque, dst: [*]u8, size: socklen_t) callconv(.C) ?[*:0]const u8;

const Userdata = struct {
    verbose_level: u32,
    precision: TstampPrecision,
    // paho-mqtt-c will copy the message to a newly allocated buffer
    // Thus use a 100KB scratch buffer for the conversion of the packet to JSON
    // 65535 / 3 * 4 = 87380 for payload encoded as base64
    scratch: []u8,
};

// header and packet pointers are invalid after this callback returns
fn capture_callback(user: ?*c_char, header: *const pcap_pkthdr, packet: [*]const c_char) callconv(.C) void {
    const userdata: *Userdata = @alignCast(@ptrCast(user.?));

    // In nano precision mode the tv_nsec from timespec is stored in tv_usec from timeval.
    // We convert Micros to Nanos so that we output standardized JSON.
    // https://github.com/the-tcpdump-group/libpcap/blob/e17fe06d6a54abc85fb17998d0cb1742d490382a/pcap-bpf.c#L1398
    const ts: timespec = switch (userdata.precision) {
        .micro => .{ .sec = header.ts.sec, .nsec = @as(isize, header.ts.usec) * 1_000 },
        .nano => .{ .sec = header.ts.sec, .nsec = header.ts.usec },
    };

    var fbs = std.io.fixedBufferStream(userdata.scratch);
    const pkt = @as([*]const u8, @ptrCast(packet))[0..header.caplen];
    packet_to_json(fbs.writer(), ts, header.len, pkt) catch |err| {
        log.err("Can't convert packet to JSON: {s}", .{@errorName(err)});
        return;
    };

    if (userdata.verbose_level > 1) {
        var io_vecs = [_]std.posix.iovec_const{
            .{ .base = fbs.buffer.ptr, .len = fbs.pos },
            .{ .base = "\n".ptr, .len = 1 },
        };
        // ignore error if we can't print the JSON message
        std.io.getStdOut().writevAll(&io_vecs) catch {};
    }
}

// use `anytype` instead of `io.AnyWriter` for improved performance
fn packet_to_json(writer: anytype, ts: timespec, len: usize, packet: []const u8) !void {
    var json_stream = std.json.writeStream(writer, .{});
    defer json_stream.deinit();
    try json_stream.beginObject();

    try json_stream.objectField("ts");
    try json_stream.beginObject();
    try json_stream.objectField("sec");
    try json_stream.write(ts.sec);
    try json_stream.objectField("nsec");
    try json_stream.write(ts.nsec);
    try json_stream.endObject();

    try json_stream.objectField("len");
    try json_stream.write(len);
    try json_stream.objectField("caplen");
    try json_stream.write(packet.len);

    try json_stream.objectField("data");
    try json_stream.beginWriteRaw();
    try json_stream.stream.writeByte('"');
    const Encoder = std.base64.standard.Encoder;
    try Encoder.encodeWriter(json_stream.stream, packet);
    try json_stream.stream.writeByte('"');
    json_stream.endWriteRaw();
    try json_stream.endObject();
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

        if (mem.eql(u8, mem.span(dev.name), "any")) {
            try tty_config.setColor(writer, .red);
            try writer.writeAll("    limitation: This device does NOT support promiscuous mode\n");
            try tty_config.setColor(writer, .reset);
        }

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

fn list_dl_header_types(writer: std.io.AnyWriter, tty_config: std.io.tty.Config, handle: *pcap_t, dlt_buf: []c_int) !void {
    const active_linktype = pcap_datalink(handle);
    for (dlt_buf) |dlt| {
        const name = pcap_datalink_val_to_name(dlt);
        const descr = pcap_datalink_val_to_description(dlt);
        try writer.print("  - [{d}] {s}: {s}", .{ dlt, name, descr });
        if (active_linktype == dlt) {
            try writer.writeAll(" [");
            try tty_config.setColor(writer, .green);
            try writer.writeAll("ACTIVE");
            try tty_config.setColor(writer, .reset);
            try writer.writeByte(']');
        }
        try writer.writeByte('\n');
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
    \\Limitation: The 'any' device does not support promiscuous mode.
    \\
    \\Usage: pcap_publisher <COMMAND> [OPTIONS]
    \\
    \\Commands:
    \\  capture [Default]        Live capture of packets from network interface
    \\  replay                   Read packets from PCAP file
    \\
    \\General Options:
    \\  -h, --help               Print help
    \\  -V, --version            Print version
    \\  -v, --verbose            Increase logging level. Can be used multiple times
    \\                           1: metadata from captured device and MQTT connection
    \\                           2: published JSON message
    \\
    \\MQTT Options:
    \\      --uri <VALUE>        URI of MQTT broker [default: tcp://localhost:1883]
    \\      --prefix <VALUE>     Prefix of MQTT topic
    \\      --client-id <VALUE>  Unique identifier for this client
    \\      --username <VALUE>   Username for MQTT broker (MQTT_USERNAME env variable)
    \\      --password <VALUE>   Password for MQTT broker (MQTT_PASSWORD env variable)
    \\
    \\Capture Options:
    \\  -d, --dev <DEVICE>         Name of captured network interface
    \\      --ts-source <ENUM>     Location where timestamp is recorded
    \\          'host' -> Host adds timestamp rather than capture device
    \\                    No commitment if timestamp will be low or high precision
    \\          'host_lowprec'         -> Host, low precision
    \\          'host_hiprec'          -> Host, high precision [Default]
    \\          'host_hiprec_unsynced' -> Host, high precision, not synced with system time
    \\          'adapter'              -> Adapter, high precision, synced with system time
    \\          'adapter_unsynced'     -> Adapter, high precision, not synced with system time
    \\      --ts-precision <ENUM>  Precision of network packet timestamps
    \\          'micro' -> microsecond precision
    \\          'nano'  -> nanosecond precision [Default]
    \\      --dl-header <VALUE>    Datalink header type
    \\      --rfmon                Enable capture of management or control frames
    \\                             in IEEE 802.11 wireless LANs. Also enable 802.11 header
    \\                             or radio information pseudo-header
    \\
    \\Replay Options:
    \\  -f, --file <PATH>        Path to .pcap file for replay
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
    var timestamp_source: TstampSource = .adapter;
    var timestamp_precision: TstampPrecision = .nano;
    var dl_header: ?c_int = null;
    var enable_rfmon = false;

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
        } else if (mem.eql(u8, "--ts-source", arg)) {
            const raw_ts_source = args.next() orelse {
                stderr.print("Missing argument for --ts-source\n", .{}) catch {};
                std.process.exit(1);
            };
            timestamp_source = TstampSource.from_str(raw_ts_source) orelse {
                stderr.print("Invalid timestamp source: {s}\n", .{raw_ts_source}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--ts-precision", arg)) {
            const raw_ts_precision = args.next() orelse {
                stderr.print("Missing argument for --ts-precision\n", .{}) catch {};
                std.process.exit(1);
            };
            timestamp_precision = TstampPrecision.from_str(raw_ts_precision) orelse {
                stderr.print("Invalid timestamp precision: {s}\n", .{raw_ts_precision}) catch {};
                std.process.exit(1);
            };
        } else if (mem.eql(u8, "--dl-header", arg)) {
            const raw_dl_header = args.next() orelse {
                stderr.print("Missing argument for --dl-header\n", .{}) catch {};
                std.process.exit(1);
            };
            switch (pcap_datalink_name_to_val(raw_dl_header)) {
                -1 => {
                    stderr.print("Invalid datalink header type: {s}\n", .{raw_dl_header}) catch {};
                    std.process.exit(1);
                },
                else => |dlt| dl_header = dlt,
            }
        } else if (mem.eql(u8, "--rfmon", arg)) {
            enable_rfmon = true;
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
        _ = pcap_set_promisc(handle, 1);
        if (enable_rfmon) _ = pcap_set_rfmon(handle, 1);
        // Immediate mode is needed because the packets should be sent directly via
        // MQTT without delay instead of batching them.
        // pcap_set_timeout() has no effect if immediate mode is active
        _ = pcap_set_immediate_mode(handle, 1);
        _ = pcap_set_snaplen(handle, 65535);
        _ = pcap_set_buffer_size(handle, 64 << 20); // 64MB

        // Check if capture device supports requested timestamp type and precision
        const ts_type_rc = pcap_set_tstamp_type(handle, @intFromEnum(timestamp_source));
        if (ts_type_rc != 0) {
            stderr.print("Failed to set timestamp type: {s}\n", .{pcap_statustostr(ts_type_rc)}) catch {};
            std.process.exit(1);
        }
        const ts_prec_rc = pcap_set_tstamp_precision(handle, @intFromEnum(timestamp_precision));
        if (ts_prec_rc != 0) {
            stderr.print("Failed to set timestamp precision: {s}\n", .{pcap_statustostr(ts_prec_rc)}) catch {};
            std.process.exit(1);
        }

        if (verbose_level > 0) {
            try stdout.print("Live capture of network device '{s}':\n", .{dev});
            try stdout.print("  timestamp source: {s}\n", .{@tagName(timestamp_source)});
            try stdout.print("  timestamp precision: {s}\n", .{@tagName(timestamp_precision)});
            try stdout.writeAll("  monitor mode (aka rfmon): ");
            if (enable_rfmon) {
                try tty_config.setColor(stdout, .green);
                try stdout.writeAll("enabled");
            } else {
                try tty_config.setColor(stdout, .red);
                try stdout.writeAll("disabled");
            }
            try tty_config.setColor(stdout, .reset);
            try stdout.writeAll("\n\n");
            try bw.flush();
        }

        const activate_rc = pcap_activate(handle);
        if (activate_rc != 0) {
            stderr.print("Failed to start capture: {s}\n", .{pcap_statustostr(activate_rc)}) catch {};
            std.process.exit(1);
        }

        if (dl_header) |dlt| {
            if (pcap_set_datalink(handle, dlt) != 0) {
                // pcap_set_datalink() only uses generic -1 error code. Retrieve the internal
                // errbuf with `pcap_geterr` for detailed error message
                stderr.print("Failed to set datalink header type: {s}\n", .{pcap_geterr(handle)}) catch {};
                std.process.exit(1);
            }
        }

        if (verbose_level > 0) {
            var dlt_buf: [*]c_int = undefined;
            const dl_list_rc = pcap_list_datalinks(handle, &dlt_buf);
            if (dl_list_rc < 0) {
                stderr.print("Failed to list datalink header types: {s}\n", .{pcap_geterr(handle)}) catch {};
                std.process.exit(1);
            }
            defer pcap_free_datalinks(dlt_buf);
            if (dl_list_rc > 0) {
                try stdout.writeAll("Supported datalink header types:\n");
                try list_dl_header_types(stdout.any(), tty_config, handle, dlt_buf[0..@intCast(dl_list_rc)]);
                try stdout.writeByte('\n');
                try bw.flush();
            }
        }

        const userdata: Userdata = .{
            .verbose_level = verbose_level,
            // If the device doesn't support nano precision, it might fallback to micro without raising an error
            // Thus get the actual precision or otherwise the timestamp calculation might be incorrect
            .precision = @enumFromInt(pcap_get_tstamp_precision(handle)),
            .scratch = try allocator.alloc(u8, 100_000),
        };
        defer allocator.free(userdata.scratch);
        while (true) {
            // Dispatch will return either if the callback was triggered 50 times or the timeout was reached
            // If rc is positive, it represents the number of captured packets
            const dispatch_rc = pcap_dispatch(handle, 50, capture_callback, @constCast(@ptrCast(&userdata)));
            if (dispatch_rc < 0) {
                log.err("Could not run capture callback: {s}", .{pcap_statustostr(dispatch_rc)});
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
