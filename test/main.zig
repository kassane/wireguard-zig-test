//! Rewrite test example to zig.
//! wireguard.h - Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

const std = @import("std");
const crypto = std.crypto;
const log = std.log.scoped(.wireguard);

const wireguard = @cImport({
    @cInclude("wireguard.h");
});

const X25519 = crypto.dh.X25519;

pub fn main() void {
    var newPeer: wireguard.wg_peer = wireguard.wg_peer{
        .flags = @bitCast(c_uint, wireguard.WGPEER_HAS_PUBLIC_KEY | wireguard.WGPEER_REPLACE_ALLOWEDIPS),
        .public_key = std.mem.zeroes([32]u8),
        .preshared_key = std.mem.zeroes([32]u8),
        .endpoint = std.mem.zeroes(wireguard.wg_endpoint),
        .last_handshake_time = std.mem.zeroes(wireguard.timespec64),
        .rx_bytes = 0,
        .tx_bytes = 0,
        .persistent_keepalive_interval = 0,
        .first_allowedip = null,
        .last_allowedip = null,
        .next_peer = null,
    };

    var newDevice: wireguard.wg_device = .{
        .name = [_]u8{ 'w', 'g', '_', 't', 'e', 's', 't', '0' } ++ [_]u8{0} ** 8, // [16]u8,
        .ifindex = 0,
        .flags = wireguard.WGDEVICE_HAS_PRIVATE_KEY | wireguard.WGDEVICE_HAS_LISTEN_PORT,
        .public_key = [_]u8{0} ** 32,
        .private_key = [_]u8{0} ** 32,
        .fwmark = 0,
        .listen_port = 1234,
        .first_peer = &newPeer,
        .last_peer = &newPeer,
    };

    const tempKeys = X25519.KeyPair.create(null) catch @panic("Failed to generate temporary keys");
    const deviceKeys = X25519.KeyPair.create(null) catch @panic("Failed to generate device keys");

    std.mem.copy(u8, &newPeer.public_key, &tempKeys.public_key);
    std.mem.copy(u8, &newDevice.private_key, &deviceKeys.secret_key);
    std.mem.copy(u8, &newDevice.public_key, &deviceKeys.public_key);

    if (wireguard.wg_add_device(&newDevice.name) < 0) {
        log.err("Unable to add device", .{});
        return;
    }

    if (wireguard.wg_set_device(&newDevice) < 0) {
        log.err("Unable to set device", .{});
        return;
    }

    listDevices();

    if (wireguard.wg_del_device(&newDevice.name) < 0) {
        log.err("Unable to delete device", .{});
        return;
    }
}

fn listDevices() void {
    var deviceNames: [*c]u8 = null;
    deviceNames = wireguard.wg_list_device_names() orelse null;

    defer std.c.free(@ptrCast(?*anyopaque, deviceNames));

    if (deviceNames == null) {
        log.err("Unable to get device names", .{});
        return;
    }

    var deviceName: [*c]u8 = deviceNames;
    while (std.mem.len(deviceName) != 0) {
        var device: [*c]wireguard.wg_device = null;
        var peer: [*c]wireguard.wg_peer = null;
        var key: wireguard.wg_key_b64_string = undefined;

        if (wireguard.wg_get_device(&device, deviceName) < 0) {
            log.err("Unable to get device", .{});
            continue;
        }

        if ((device.*.flags & wireguard.WGDEVICE_HAS_PUBLIC_KEY) != 0) {
            wireguard.wg_key_to_base64(&key, &device.*.public_key);
            log.info("{s} has public key {s}", .{ deviceName, &key });
        } else {
            log.info("{s} has no public key.", .{deviceName});
        }

        peer = device.*.first_peer;
        while (peer != null) {
            wireguard.wg_key_to_base64(&key, &peer.*.public_key);
            log.info("peer {s}\n", .{&key});
            peer = peer.*.next_peer;
        }

        wireguard.wg_free_device(device);
        deviceName += std.mem.len(deviceName) + 1;
    }
}
