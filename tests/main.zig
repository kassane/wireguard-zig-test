//! Rewrite test example to zig.
//! wireguard.h - Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const wireguard = @cImport(@cInclude("wireguard.h"));

const log = std.log.scoped(.wireguard);

pub fn main() void {
    var new_peer: wireguard.wg_peer = wireguard.wg_peer{
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

    var new_device: wireguard.wg_device = wireguard.wg_device{
        .name = [_]u8{ 'w', 'g', '_', 't', 'e', 's', 't', '0' } ++ [_]u8{0} ** 8, // [16]u8
        .ifindex = 0,
        .flags = @bitCast(c_uint, wireguard.WGDEVICE_HAS_PRIVATE_KEY | wireguard.WGDEVICE_HAS_LISTEN_PORT),
        .public_key = std.mem.zeroes([32]u8),
        .private_key = std.mem.zeroes([32]u8),
        .fwmark = 0,
        .listen_port = 1234,
        .first_peer = &new_peer,
        .last_peer = &new_peer,
    };

    // ================================Generating KeyPair======================================
    // C API
    // var temp_private_key: wireguard.wg_key = undefined;
    //
    // wireguard.wg_generate_private_key(&temp_private_key);
    // wireguard.wg_generate_public_key(&new_peer.public_key, &temp_private_key);
    // wireguard.wg_generate_private_key(&new_device.private_key);

    // Zig API
    const temp_keys = X25519.KeyPair.create(null) catch @panic("Don't generating temp keys");
    const device_keys = X25519.KeyPair.create(null) catch @panic("Don't generating keys device");

    std.mem.copy(u8, &new_peer.public_key, &temp_keys.public_key);
    std.mem.copy(u8, &new_device.private_key, &device_keys.secret_key);
    std.mem.copy(u8, &new_device.public_key, &device_keys.public_key);
    // ========================================================================================

    if (wireguard.wg_add_device(&new_device.name) < 0) {
        log.err("Unable to add device", .{});
        std.os.exit(1);
    }

    if (wireguard.wg_set_device(&new_device) < 0) {
        log.err("Unable to set device", .{});
        std.os.exit(1);
    }

    list_devices();

    if (wireguard.wg_del_device(&new_device.name) < 0) {
        log.err("Unable to delete device", .{});
        std.os.exit(1);
    }
}

fn list_devices() void {
    var device_names: ?[*c]u8 = undefined; // optional pointer (don't need C malloc/free)
    var device_name: [*c]u8 = undefined;
    var len: usize = undefined;
    device_names = wireguard.wg_list_device_names() orelse null;

    if ((device_names == null)) {
        log.err("Unable to get device names", .{});
        std.os.exit(1);
    }

    defer if ((device_names.? != null)) @panic("leak");

    {
        _ = blk: {
            device_name = device_names.?; // Value orelse null
            break :blk blk_1: {
                const tmp = 0;
                len = tmp;
                break :blk_1 tmp;
            };
        };
        while ((blk: {
            const tmp = std.mem.len(device_name);
            len = tmp;
            break :blk tmp;
        }) != 0) : (device_name += len +% 1) {
            var device: [*c]wireguard.wg_device = undefined;
            var peer: [*c]wireguard.wg_peer = undefined;
            var key: wireguard.wg_key_b64_string = undefined;
            if (wireguard.wg_get_device(&device, device_name) < 0) {
                log.err("Unable to get device", .{});
                continue;
            }
            var msg: []const u8 = undefined;
            if ((device.*.flags & wireguard.WGDEVICE_HAS_PUBLIC_KEY) != 0) {
                wireguard.wg_key_to_base64(&key, &device.*.public_key);

                var bf: []u8 = undefined;
                msg = std.fmt.bufPrint(bf, "{s} has public key {s}", .{ device_name, &key }) catch unreachable;
            } else {
                log.info("{s} has no public key.", .{device_name});
            }
            {
                peer = device.*.first_peer;
                while (peer != null) : (peer = peer.*.next_peer) {
                    wireguard.wg_key_to_base64(&key, &peer.*.public_key);
                    log.info("{s} - peer {s}\n", .{ msg, &key });
                }
            }
            wireguard.wg_free_device(device);
        }
    }
}

test "Recursively references all the declarations inside" {
    const testing = std.testing;
    testing.refAllDeclsRecursive(@This());
}
