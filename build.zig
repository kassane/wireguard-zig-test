const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .whitelist = permissive_targets,
    });
    const optimize = b.standardOptimizeOption(.{});

    const libwg = b.addStaticLibrary(.{
        .name = "wireguard",
        .target = target,
        .optimize = optimize,
    });
    libwg.addCSourceFile("vendor/wireguard.c", &[_][]const u8{
        "-Wall",
    });
    libwg.linkLibC();

    const executable = b.addExecutable(.{
        .name = "wireguard-zig",
        .target = target,
        .optimize = optimize,
        .root_source_file = .{
            .path = "test/main.zig",
        },
    });
    executable.linkLibrary(libwg);
    executable.addIncludePath("vendor");
    executable.linkLibC();

    b.installArtifact(executable);

    const run_step = b.step("run", b.fmt("Run {s} app", .{executable.name}));
    run_step.dependOn(&executable.step);
}

const permissive_targets: []const std.zig.CrossTarget = &.{
    .{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .gnu,
    },
    .{
        .cpu_arch = .x86,
        .os_tag = .linux,
        .abi = .gnu,
    },
    .{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    },
    .{
        .cpu_arch = .x86,
        .os_tag = .linux,
        .abi = .musl,
    },
    .{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .gnu,
    },
    .{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .musl,
    },
    // .{
    //     .cpu_arch = .riscv64,
    //     .os_tag = .linux,
    //     .abi = .gnu,
    // https://github.com/ziglang/zig/issues/3340
    // },
    .{
        .cpu_arch = .riscv64,
        .os_tag = .linux,
        .abi = .musl,
    },
    .{
        .cpu_arch = .powerpc64,
        .os_tag = .linux,
        .abi = .gnu,
    },
    .{
        .cpu_arch = .powerpc64,
        .os_tag = .linux,
        .abi = .musl,
    },
};
// see all targets list:
// run: zig targets | jq .libc (json format)
