# Changelog — goodnet-link-ws

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t`.

## [Unreleased]

### RFC 6455 §5.4 fragmentation reassembly

Inbound fragmented messages are reassembled across continuation
frames up to a 16 MiB cap. The per-frame ceiling stays at
`kMaxFramePayload = 64 KiB`, but a logical message can now be
split across many frames without breaking the upper read.
Tested with a 70 KiB cross-frame message that spans the
single-frame boundary.

### 64-bit-word masking + RFC 7692 stance

The masking step in the wire path now applies the XOR mask in
64-bit-word strides, with edge-size unit tests covering payload
lengths that are not word-aligned. The README states explicitly
that RFC 7692 `permessage-deflate` is not implemented — a
client offering the extension in handshake gets a response with
no `Sec-WebSocket-Extensions` echo, and the connection falls
back to uncompressed frames per RFC 7692 §5.1.

### Trust + backpressure hardening

`::ffff:127.x` IPv4-mapped IPv6 addresses are now classified as
loopback in the trust resolver, so loopback bridges land in the
right trust class. The recv path treats `LIMIT_REACHED` as
transient — the WebSocket session no longer counts it toward
disconnect; a full park, on par with the TCP / TLS / IPC
siblings, is the open follow-up.

### Composer-carrier refactor

The WebSocket link no longer binds a TCP socket directly; it
rides a `LinkCarrier(gn.link.tcp)` (or `gn.link.tls` for
`wss://`). The framing layer becomes a pure composer over the
carrier's `notify_inbound_bytes`, which keeps the WS plugin
free of socket lifecycle concerns and lets it reuse the TCP /
TLS sibling for the multi-threaded `io_context` pool and the
recv-buffer backpressure machinery.

## [1.0.0-rc1] — 2026-05-08

Initial release. Brings the legacy in-tree `links/ws` link
forward as a v1 GoodNet link plugin.

### Added

- WebSocket transport with `ws://host:port/path` URI scheme.
  Wraps the handshake + framing layer per RFC 6455; surfaces
  unmasked payloads through `host_api->notify_inbound_bytes`
  with the same semantics as the TCP transport, so upper layers
  can swap schemes without code changes.
- Multi-threaded `io_context` worker pool sized to half
  `hardware_concurrency()`.
- SDK link teardown conformance — disconnect emit is serialized
  with the shutdown flag, and every published conn is tracked
  so caller-thread `shutdown()` emits the matching
  `DISCONNECTED` notification for every active session.
- Ping-flood / pong-overflow disconnect path with extended
  deadlines under sanitiser runs to avoid flaky test failures.
- Host-authority parsing for IPv6 bracketed forms
  (`[::1]:8080`).
