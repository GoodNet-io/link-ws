# goodnet-link-ws

WebSocket transport for GoodNet. Wraps a `ws://host:port/path`
endpoint with the WebSocket framing handshake; downgrades cleanly
to the same byte stream the TCP transport publishes, so the kernel
sees identical `notify_inbound_bytes` semantics on either scheme.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input. From this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_ws.so
nix run .#test          # vanilla ctest
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `ws` scheme. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
