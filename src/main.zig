const std = @import("std");
const mem = std.mem;
const log = std.log;
const sockaddr = std.c.sockaddr;
const socklen_t = std.c.socklen_t;
const timeval = std.c.timeval;
const timespec = std.posix.timespec;
const AF = std.posix.AF;
const mqtt = @import("paho_mqtt_zig");
const DotEnv = @import("dot_env.zig");

// size of linked list of PUBLISH messages waiting to be processed
const MAX_BUFFERED_MSG = 500;

const ExitSignal = enum(u32) {
    Continue,
    Shutdown,
    Failure,
};
// If the exit singal is not `Continue`, any long running function should exit with `error.Cancelled`.
var exit_signal = std.atomic.Value(u32).init(@intFromEnum(ExitSignal.Continue));

const pcap_t = opaque {};

const pcap_if = extern struct {
    next: ?*pcap_if,
    name: [*:0]const u8, // name to hand to "pcap_open_live()"
    description: ?[*:0]const u8, // textual description of interface, or NULL
    addresses: ?*pcap_addr,
    flags: pcap_flags,
};

const pcap_flags = packed struct(c_uint) {
    loopback: bool,
    up: bool,
    running: bool,
    wireless: bool,
    connection_status: enum(u2) {
        unknown = 0x0,
        connected = 0x1,
        disconnected = 0x2,
        not_applicable = 0x3,
    },
    reserved: std.meta.Int(.unsigned, @bitSizeOf(c_uint) - 6) = 0,
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
        const map: std.StaticStringMap(TstampSource) = .initComptime(.{
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
        const map: std.StaticStringMap(TstampPrecision) = .initComptime(.{
            .{ "micro", .micro },
            .{ "nano", .nano },
        });
        return map.get(name);
    }
};

const pcap_handler = *const fn (user: ?*c_char, header: *const pcap_pkthdr, packet: [*]const c_char) callconv(.C) void;

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
    mqtt_client: mqtt.MqttAsync,
    prefixed_topic: [:0]const u8,
};

// header and packet pointers are invalid after this callback returns
fn capture_cb(user: ?*c_char, header: *const pcap_pkthdr, packet: [*]const c_char) callconv(.C) void {
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

    const properties = [_]mqtt.MqttProperty{
        .from_byte(.PAYLOAD_FORMAT_INDICATOR, 1),
        .from_utf8_str(.CONTENT_TYPE, "application/json"),
        .from_uf8_str_pair(.USER_PROPERTY, "schema", "1"),
        .from_uf8_str_pair(.USER_PROPERTY, "sensor", "pcap"),
    };
    var call_opt: mqtt.MqttAsync.CallOptions = .{
        .context = @ptrCast(userdata),
        .onSuccess5 = &sendMsg_success_cb,
        .onFailure5 = &sendMsg_failure_cb,
    };
    var msg: mqtt.MqttMessage = .{
        .payloadlen = @intCast(fbs.pos),
        .payload = fbs.buffer.ptr,
        .qos = .FireAndForget,
        .retained = @intFromBool(false),
        .properties = .{ .count = properties.len, .array = @constCast(@ptrCast(&properties)) },
    };
    userdata.mqtt_client.sendMessage(userdata.prefixed_topic.ptr, &msg, &call_opt) catch |err| switch (err) {
        error.MaxBufferedMessages => {
            if (pending_delivery_tokens(userdata.mqtt_client)) |queue_size| {
                log.warn("could not publish message, because buffer is full (delivery queue: {d}/{d})", .{ queue_size, MAX_BUFFERED_MSG });
            } else {
                log.warn("could not publish message, because buffer is full", .{});
            }
        },
        else => log.warn("can't start to send message: {s}", .{@errorName(err)}),
    };
}

fn sendMsg_success_cb(context: ?*anyopaque, response: *mqtt.MqttAsync.SuccessData5) callconv(.C) void {
    const userdata: *Userdata = @alignCast(@ptrCast(context.?));
    const msg = response.alt.@"pub".message;
    if (msg.payload) |payload| {
        const topic = mem.span(response.alt.@"pub".destinationName); // TODO check for null
        const payload_slice = payload[0..@intCast(msg.payloadlen)];
        // The "protocol" logging level of paho-mqtt-c already outputs all published
        // messages, but it truncates after 20 bytes.
        if (userdata.verbose_level > 1) {
            // `fmt.print` emits separate `write` syscalls for every format argument
            var io_vecs = [_]std.posix.iovec_const{
                .{ .base = topic.ptr, .len = topic.len },
                .{ .base = " -> ".ptr, .len = 4 },
                .{ .base = payload_slice.ptr, .len = payload_slice.len },
                .{ .base = "\n".ptr, .len = 1 },
            };
            // ignore error if we can't print the JSON message
            std.io.getStdOut().writevAll(&io_vecs) catch {};
        }
    } else {
        // If the connection to the broker is not yet established and a lot of messages
        // are published, `maxBufferedMessages` will cause the payload and topic to be discarded.
        log.debug("sendMsg success callback: discarded payload and topic", .{});
    }
}

fn sendMsg_failure_cb(context: ?*anyopaque, response: *mqtt.MqttAsync.FailureData5) callconv(.C) void {
    _ = context;
    if (response.message) |fail_msg| {
        log.err("send message failed (code {}, reason {}): {s}", .{
            response.code,
            @intFromEnum(response.reasonCode),
            fail_msg,
        });
    } else {
        log.err("send message failed (code {}, reason {})", .{
            response.code,
            @intFromEnum(response.reasonCode),
        });
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

fn connectToBroker(client: mqtt.MqttAsync, opt: *const mqtt.MqttAsync.ConnectOptions) !bool {
    const State = enum(u32) { Start, Success, Failure };
    var shared_context = std.atomic.Value(u32).init(@intFromEnum(State.Start));
    const cb = struct {
        fn onSuccess5(context: ?*anyopaque, response: *mqtt.MqttAsync.SuccessData5) callconv(.C) void {
            _ = response;
            var my_context: *@TypeOf(shared_context) = @alignCast(@ptrCast(context));
            _ = my_context.store(@intFromEnum(State.Success), .release);
            std.Thread.Futex.wake(my_context, 1);
        }

        fn onFailure5(context: ?*anyopaque, response: *mqtt.MqttAsync.FailureData5) callconv(.C) void {
            var my_context: *@TypeOf(shared_context) = @alignCast(@ptrCast(context));
            if (response.message) |fail_msg| {
                log.err("connection to MQTT broker failed (code {}, reason {}): {s}", .{
                    response.code,
                    @intFromEnum(response.reasonCode),
                    fail_msg,
                });
            } else {
                log.err("connection to MQTT broker failed (code {}, reason {})", .{
                    response.code,
                    @intFromEnum(response.reasonCode),
                });
            }
            _ = my_context.store(@intFromEnum(State.Failure), .release);
            std.Thread.Futex.wake(my_context, 1);
        }
    };

    var connect_opt: mqtt.MqttAsync.ConnectOptions = opt.*;
    connect_opt.context = &shared_context;
    connect_opt.onSuccess5 = &cb.onSuccess5;
    connect_opt.onFailure5 = &cb.onFailure5;
    try client.connect(&connect_opt);

    var conn_state: State = undefined;
    while (true) {
        if (@as(ExitSignal, @enumFromInt(exit_signal.load(.acquire))) != .Continue)
            return error.Cancelled;
        conn_state = @enumFromInt(shared_context.load(.acquire));
        if (conn_state != .Start) break;
        std.Thread.Futex.wait(&shared_context, @intFromEnum(State.Start));
    }
    return switch (conn_state) {
        .Start => unreachable,
        .Failure => false,
        .Success => true,
    };
}

fn create_mqtt_client(
    client_id: [:0]const u8,
    uri: [:0]const u8,
    username: ?[:0]const u8,
    password: ?[:0]const u8,
) !mqtt.MqttAsync {
    var create_opt: mqtt.MqttAsync.CreateOptions = .{ .MQTTVersion = .v5, .sendWhileDisconnected = 1, .maxBufferedMessages = MAX_BUFFERED_MSG };
    const client_handle = mqtt.MqttAsync.createWithOptions(uri, client_id, .None, null, &create_opt) catch |err| {
        log.err("can't create MQTT Client: {s}", .{@errorName(err)});
        return error.createClient;
    };
    client_handle.setCallbacks(null, &onConnectionLost, &onMessageArrived, null) catch |err| {
        log.err("can't register 'onConnectionLost' and 'onMessageArrived' callback: {s}", .{@errorName(err)});
        return error.registerCallback;
    };
    client_handle.setConnected(null, &onConnect) catch |err| {
        log.err("can't register callback for reconnect to broker: {s}", .{@errorName(err)});
        return error.registerCallback;
    };
    client_handle.setDisconnected(null, &onDisconnect) catch |err| {
        log.err("can't register 'onDisconnect' callback: {s}", .{@errorName(err)});
        return error.registerCallback;
    };

    const ssl_cb = struct {
        // https://github.com/eclipse/paho.mqtt.c/blob/6b1e202a701ffcdaa277b5644ed291287a70a7aa/src/SSLSocket.c#L97
        // first paho-mqtt-c retrieves the error code with OpenSSL `SSL_get_error`
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html
        // Then it passes a pointer to this function and the error code to `ERR_print_errors_cb`
        // https://www.openssl.org/docs/manmaster/man3/ERR_print_errors.html
        fn sslErrCB(str: [*]const u8, len: usize, u: *anyopaque) callconv(.C) c_int {
            _ = u;
            // Usually OpenSSL error logs end with a new line. Remove it because
            // our Zig logging handler already adds `\n`.
            const new_len = if (len > 0 and str[len - 1] == '\n') len - 1 else len;
            log.err("OpenSSL: {s}", .{str[0..new_len]});
            // This callback will be called multiple times if there are cascading errors.
            // Return codes 0 and smaller abort this loop and only print the first error.
            // https://github.com/openssl/openssl/blob/f6ce48f5b8ad4d8d748ea87d2490cbed08db9936/crypto/err/err_prn.c#L44
            return 1;
        }
    };
    var ssl_opt: mqtt.SslOptions = .{
        .enableServerCertAuth = 0,
        .verify = 1,
        .ssl_error_cb = &ssl_cb.sslErrCB,
    };
    const connect_opt: mqtt.MqttAsync.ConnectOptions = .{
        .username = if (username) |u| @constCast(u).ptr else null,
        .password = if (password) |p| @constCast(p).ptr else null,
        .ssl = &ssl_opt,
        .automaticReconnect = 1,
        .maxRetryInterval = 15,
    };
    while (true) {
        if (@as(ExitSignal, @enumFromInt(exit_signal.load(.acquire))) != .Continue)
            return error.Cancelled;
        const isConnected = connectToBroker(client_handle, &connect_opt) catch |err| {
            log.err("can't start to connect to MQTT broker: {s}", .{@errorName(err)});
            return err;
        };

        if (isConnected) break;
        log.info("Retrying to connect to the MQTT broker in 1 second", .{});
        std.time.sleep(1 * std.time.ns_per_s);
    }
    return client_handle;
}

fn pending_delivery_tokens(client: mqtt.MqttAsync) ?usize {
    var tokens: ?[*]mqtt.MqttAsync.AsyncToken = null;
    client.getPendingTokens(&tokens) catch |getTokens_err| {
        log.warn("can't get pending delivery tokens: {s}", .{@errorName(getTokens_err)});
        return null;
    };
    defer if (tokens) |t| mqtt.MqttAsync.free(t);

    if (tokens) |tok_list| {
        var idx: usize = 0;
        while (@intFromEnum(tok_list[idx]) != -1) : (idx += 1) {}
        return idx;
    }
    return 0;
}

// Don't use `std.log` here, because it does not allow changing the logging
// level at runtime. We set the trace level in main with `MqttAsync.setTraceLevel`,
// so we don't need to do any filtering here.
//
// Note about newfstatat syscall:
// Log_formatTraceEntry constructs the `message` string. It calls `localtime`,
// which calls `newfstatat`.
fn mqttTraceCallback(level: mqtt.MqttAsync.TraceLevel, message: [*:0]u8) callconv(.C) void {
    const level_str = @tagName(level);
    const msg_slice = mem.span(message);
    var io_vecs = [_]std.posix.iovec_const{
        .{ .base = "paho (".ptr, .len = 6 },
        .{ .base = level_str.ptr, .len = level_str.len },
        .{ .base = "): ".ptr, .len = 3 },
        .{ .base = msg_slice.ptr, .len = msg_slice.len },
        .{ .base = "\n".ptr, .len = 1 },
    };
    // ignore error if we can't print the JSON message
    std.io.getStdOut().writevAll(&io_vecs) catch {};
}

fn onConnectionLost(context: ?*anyopaque, cause: ?[*:0]u8) callconv(.C) void {
    _ = context;
    if (cause) |c| {
        log.err("lost connection to MQTT broker: {s}", .{c});
    } else {
        log.err("lost connection to MQTT broker", .{});
    }
}

fn onConnect(context: ?*anyopaque, cause: ?[*:0]u8) callconv(.C) void {
    _ = context;
    _ = cause; // useless information: "connect onSuccess called"
    log.info("Connected to MQTT broker", .{});
}

fn onDisconnect(
    context: ?*anyopaque,
    properties: *mqtt.MqttProperties,
    reasonCode: mqtt.MqttReasonCode,
) callconv(.C) void {
    _ = context;
    _ = properties;
    _ = mqtt.reason(reasonCode) catch |err| {
        log.warn("received disconnect packet: {s}", .{@errorName(err)});
        return;
    };
    log.warn("received disconnect packet without reason code", .{});
}

fn onMessageArrived(
    context: ?*anyopaque,
    topicName: [*:0]u8,
    topicLen: c_int,
    message: *mqtt.MqttMessage,
) callconv(.C) c_int {
    _ = context;
    _ = topicName;
    _ = topicLen;
    _ = message;
    return 1; // message has been successfully handled
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
        if (dev.flags.loopback) {
            try tty_config.setColor(writer, .yellow);
            try writer.writeAll("loopback");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if (dev.flags.up) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .cyan);
            try writer.writeAll("up");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if (dev.flags.running) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .blue);
            try writer.writeAll("running");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        if (dev.flags.wireless) {
            if (needs_comma) try writer.writeAll(", ");
            try tty_config.setColor(writer, .magenta);
            try writer.writeAll("wireless");
            try tty_config.setColor(writer, .reset);
            try tty_config.setColor(writer, .dim);
            needs_comma = true;
        }
        switch (dev.flags.connection_status) {
            .unknown => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .yellow);
                try writer.writeAll("unknown status");
            },
            .connected => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .green);
                try writer.writeAll("connected");
            },
            .disconnected => {
                if (needs_comma) try writer.writeAll(", ");
                try tty_config.setColor(writer, .red);
                try writer.writeAll("disconnected");
            },
            .not_applicable => {},
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

    var dot_env: DotEnv = .{};
    try dot_env.read_file(allocator);
    defer dot_env.deinit(allocator);

    if (verbose_level > 0) {
        // paho-mqtt-c uses `Log_output` instead of `Log` in `Log_initialize`,
        // which ignores the logging level. As a workaround we only register
        // the trace callback if verbose logging is enabled, so that we don't
        // output the paho-mqtt-c "Trace Output" metadata.
        // https://github.com/eclipse/paho.mqtt.c/blob/master/src/Log.c#L199
        mqtt.MqttAsync.setTraceLevel(switch (verbose_level) {
            0 => unreachable,
            1 => .Error,
            2 => .Protocol,
            else => .Maximum,
        });
        mqtt.MqttAsync.setTraceCallback(&mqttTraceCallback);
    }
    var init_opt: mqtt.InitOptions = .{ .do_openssl_init = 1 };
    mqtt.MqttAsync.globalInit(&init_opt);

    const cid = client_id orelse "pcap_publisher";
    const mqtt_client = try create_mqtt_client(
        cid,
        broker_uri orelse "tcp://localhost:1883",
        username orelse try dot_env.get(allocator, "MQTT_USERNAME"),
        password orelse try dot_env.get(allocator, "MQTT_PASSWORD"),
    );

    if (capture_dev) |dev| {
        const prefixed_topic = try std.fmt.allocPrintZ(allocator, "{s}pcap/{s}/dev/{s}", .{ prefix orelse "", cid, dev });
        defer allocator.free(prefixed_topic);

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
            try stdout.writeAll("  WiFi monitor mode (aka rfmon): ");
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
            .mqtt_client = mqtt_client,
            .prefixed_topic = prefixed_topic,
        };
        defer allocator.free(userdata.scratch);
        while (true) {
            // Dispatch will return either if the callback was triggered 50 times or the timeout was reached
            // If rc is positive, it represents the number of captured packets
            const dispatch_rc = pcap_dispatch(handle, 50, &capture_cb, @constCast(@ptrCast(&userdata)));
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
