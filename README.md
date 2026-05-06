# goodnet-link-ws

WebSocket transport for GoodNet. Wraps a `ws://host:port/path`
endpoint with the WebSocket framing handshake; downgrades cleanly
to the same byte stream the TCP transport publishes, so the kernel
sees identical `notify_inbound_bytes` semantics on either scheme.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-link-ws
# result/lib/goodnet/plugins/libgoodnet_link_ws.so
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/links/ws
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `ws` scheme. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.md`
