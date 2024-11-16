const std = @import("std");
const Step = std.Build.Step;
const ResolvedTarget = std.Build.ResolvedTarget;
const OptimizeMode = std.builtin.OptimizeMode;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "pcap_publisher",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    if (b.systemIntegrationOption("pcap", .{})) {
        exe.linkSystemLibrary("pcap");
    } else {
        const lib_pcap = build_pcap(b, target, optimize);
        exe.linkLibrary(lib_pcap);
    }

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

fn build_pcap(b: *std.Build, target: ResolvedTarget, optimize: OptimizeMode) *Step.Compile {
    const dep_pcap = b.dependency("pcap", .{});

    const lib_pcap = b.addStaticLibrary(.{
        .name = "pcap",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_pcap.addCSourceFiles(.{
        .root = dep_pcap.path("."),
        .files = &.{
            "pcap.c",        "gencode.c",   "optimize.c",   "nametoaddr.c", "etherent.c",
            "fmtutils.c",    "pcap-util.c", "savefile.c",   "sf-pcap.c",    "sf-pcapng.c",
            "pcap-common.c", "bpf_image.c", "bpf_filter.c", "bpf_dump.c",
        },
    });
    if (target.result.os.tag == .linux) lib_pcap.addCSourceFiles(.{
        .root = dep_pcap.path("."),
        .files = &.{ "pcap-linux.c", "pcap-netfilter-linux.c", "fad-getad.c" },
    });
    lib_pcap.addIncludePath(dep_pcap.path("."));

    const config_h_values = .{
        .HAVE___ATOMIC_LOAD_N = "1",
        .HAVE___ATOMIC_STORE_N = "1",
        .HAVE_ASPRINTF = "1",
        .HAVE_DECL_ETHER_HOSTTON = "1",
        .HAVE_ETHER_HOSTTON = "1",
        .HAVE_FSEEKO = "1",
        .HAVE_GNU_STRERROR_R = "1",
        .HAVE_INTTYPES_H = "1",
        .HAVE_LINUX_GETNETBYNAME_R = "1",
        .HAVE_LINUX_GETPROTOBYNAME_R = "1",
        .HAVE_LINUX_NET_TSTAMP_H = "1",
        .HAVE_LINUX_SOCKET_H = "1",
        .HAVE_LINUX_USBDEVICE_FS_H = "1",
        .HAVE_NETPACKET_PACKET_H = "1",
        .HAVE_SNPRINTF = "1",
        .HAVE_SOCKLEN_T = "1",
        .HAVE_STDINT_H = "1",
        .HAVE_STRING_H = "1",
        .HAVE_STRLCAT = "1",
        .HAVE_STRLCPY = "1",
        .HAVE_STRTOK_R = "1",
        .HAVE_STRUCT_TPACKET_AUXDATA_TP_VLAN_TCI = "1",
        .HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE = "1",
        .HAVE_UNISTD_H = "1",
        .HAVE_VASPRINTF = "1",
        .HAVE_VSYSLOG = "1",
        .INET6 = "1",
        .NETINET_ETHER_H_DECLARES_ETHER_HOSTTON = "1",
        .PACKAGE_NAME = "pcap",
        .PACKAGE_VERSION = "1.10.5",
        .PCAP_SUPPORT_NETFILTER = "1",
        .SIZEOF_TIME_T = "8",
        .SIZEOF_VOID_P = "8",
        .STDC_HEADERS = "1",
    };
    const config_h = b.addConfigHeader(.{
        .style = .{ .cmake = dep_pcap.path("cmakeconfig.h.in") },
        .include_path = "config.h",
    }, config_h_values);
    lib_pcap.addIncludePath(config_h.getOutput().dirname());

    const cmd_lex = b.addSystemCommand(&.{ "lex", "-P", "pcap_" });
    const scanner_h = cmd_lex.addPrefixedOutputFileArg("--header-file=", "scanner.h");
    cmd_lex.addArg("--nounput");
    cmd_lex.addArg("-o");
    const scanner_c = cmd_lex.addOutputFileArg("scanner.c");
    cmd_lex.addFileArg(dep_pcap.path("scanner.l"));

    const grammar_y = b.addConfigHeader(.{
        .style = .{ .cmake = dep_pcap.path("grammar.y.in") },
        .include_path = "grammar.y",
    }, .{ .REENTRANT_PARSER = "%define api.pure" });

    const cmd_bison = b.addSystemCommand(&.{ "bison", "-p", "pcap_" });
    const grammar_h = cmd_bison.addPrefixedOutputFileArg("--header=", "grammar.h");
    cmd_bison.addArg("-o");
    const grammar_c = cmd_bison.addOutputFileArg("grammar.c");
    cmd_bison.addFileArg(grammar_y.getOutput());

    const scanner_o = b.addObject(.{
        .name = "scanner",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    scanner_o.addCSourceFile(.{ .file = scanner_c });
    scanner_o.addIncludePath(config_h.getOutput().dirname());
    scanner_o.addIncludePath(grammar_h.dirname());
    scanner_o.addIncludePath(dep_pcap.path("."));
    lib_pcap.addObject(scanner_o);
    lib_pcap.addIncludePath(scanner_h.dirname()); // required by gencode.c

    const grammar_o = b.addObject(.{
        .name = "grammar",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    grammar_o.addIncludePath(config_h.getOutput().dirname());
    grammar_o.addIncludePath(grammar_h.dirname());
    grammar_o.addIncludePath(scanner_h.dirname());
    grammar_o.addIncludePath(dep_pcap.path("."));
    grammar_o.addCSourceFile(.{ .file = grammar_c });
    lib_pcap.addObject(grammar_o);
    lib_pcap.addIncludePath(grammar_h.dirname()); // required by gencode.c

    return lib_pcap;
}
