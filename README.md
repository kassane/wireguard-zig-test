# wireguard-zig

This project is experimental on the possibility to use zig (toolchain and language) with Wireguard VPN.

## Requirements

 * [Zig v0.11 or master](https://ziglang.org/download)
 * [Wireguard](https://www.wireguard.com)


## How to Run

See CI test

```bash
$> zig build
$> sudo zig-out/bin/wireguard-zig
info(wireguard): wg_test0 has public key +oQRkWKK/fdi5JoLah7R9JIPI6Hg1TsaPHA2DkGjSQw=
info(wireguard):  - peer vEtCZE5RZDDZseZLXJaR6q7yVqRfb0/VjijDZpikWwY=
```

# More Information

WireGuard&reg; was created and developed by Jason A. Donenfeld. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld [@zx2c4]. See https://www.wireguard.com/ for more information

This project is not approved, sponsored or affiliated with WireGuard or with the community.

- The whitepaper https://www.wireguard.com/papers/wireguard.pdf
- The Wikipedia page https://en.wikipedia.org/wiki/WireGuard 
