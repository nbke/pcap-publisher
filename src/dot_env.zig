const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const Self = @This();

map: std.StringHashMapUnmanaged([:0]const u8) = .{},

pub fn read_file(self: *Self, allocator: Allocator) !void {
    const file = std.fs.cwd().openFile(".env", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close();

    var buffered_reader = std.io.bufferedReader(file.reader());
    try self.parse(allocator, buffered_reader.reader().any());
}

pub fn deinit(self: *Self, allocator: Allocator) void {
    var iter = self.map.iterator();
    while (iter.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    self.map.deinit(allocator);
}

pub fn get(self: *Self, gpa: Allocator, name: []const u8) !?[:0]const u8 {
    if (self.map.get(name)) |val| return val;

    if (builtin.os.tag == .windows) {
        const key_w = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, name);
        defer gpa.free(key_w);
        if (std.process.getenvW(key_w)) |val_w| {
            const val = try std.unicode.wtf16LeToWtf8AllocZ(gpa, val_w);
            try self.map.putNoClobber(gpa, name, val);
            return val;
        }
    } else {
        if (std.posix.getenv(name)) |val| {
            const val_z = try gpa.dupeZ(u8, val);
            try self.map.putNoClobber(gpa, name, val_z);
            return val_z;
        }
    }
    return null;
}

fn parse(self: *Self, allocator: Allocator, r: std.io.AnyReader) !void {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(buf[0..]);
    var state: enum { Start, Key, Value } = .Start;
    var value_entry: ?*[]const u8 = null;
    while (true) switch (state) {
        .Start => switch (r.readByte() catch return) {
            ' ', '\t', '\n' => {},
            else => |char| {
                // fbs was not used yet or was reset, so we could write buf.len bytes.
                // But we only want to write 1 byte, therefore this always succeeds.
                _ = fbs.write(&.{char}) catch unreachable;
                state = .Key;
            },
        },
        .Key => {
            r.streamUntilDelimiter(fbs.writer(), '=', buf.len - fbs.pos) catch return error.InvalidKey;
            const gop_result = try self.map.getOrPut(allocator, fbs.getWritten());
            if (gop_result.found_existing) {
                allocator.free(gop_result.value_ptr.*);
                gop_result.value_ptr.* = undefined;
            } else {
                gop_result.key_ptr.* = try allocator.dupe(u8, fbs.getWritten());
            }
            value_entry = gop_result.value_ptr;
            fbs.reset();
            state = .Value;
        },
        .Value => {
            r.streamUntilDelimiter(fbs.writer(), '\n', buf.len) catch |err| switch (err) {
                error.EndOfStream => {},
                else => return error.InvalidValue,
            };
            value_entry.?.* = try allocator.dupeZ(u8, fbs.getWritten());
            fbs.reset();
            value_entry = null;
            state = .Start;
        },
    };
}

fn test_input(input: []const u8) !Self {
    var fbs = std.io.fixedBufferStream(input[0..]);
    var dot_env: Self = .{};
    try dot_env.parse(std.testing.allocator, fbs.reader().any());
    return dot_env;
}

test "empty input" {
    var a = try test_input("");
    defer a.deinit(std.testing.allocator);

    var b = try test_input("\n");
    defer b.deinit(std.testing.allocator);

    var c = try test_input(" ");
    defer c.deinit(std.testing.allocator);

    var d = try test_input(" \t\n");
    defer d.deinit(std.testing.allocator);

    var e = try test_input(" \n ");
    defer e.deinit(std.testing.allocator);
}

test "normal usage" {
    const input =
        \\TEST1=hello
        \\ WORLD=world
        \\WORLD=space
        \\case_SENSITIVE=123
        \\987=123.456
        \\
    ;

    var dot_env = try test_input(input);
    defer dot_env.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, dot_env.map.get("TEST1").?, "hello");
    try std.testing.expectEqualSlices(u8, dot_env.map.get("WORLD").?, "space");
    try std.testing.expectEqualSlices(u8, dot_env.map.get("case_SENSITIVE").?, "123");
    try std.testing.expectEqualSlices(u8, dot_env.map.get("987").?, "123.456");
}
