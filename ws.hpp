// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws.hpp
/// @brief  RFC 6455 WebSocket transport (`ws://`) — composer-mode.
///
/// WS framing layered on top of a `gn.link.<scheme>` L1 carrier
/// (today `tcp`; `tls` for the `wss://` slice). No own asio I/O —
/// every byte hop goes through the carrier, the upgrade handshake
/// runs as application bytes the carrier transports unchanged.
///
/// The HTTP/1.1 upgrade specified by RFC 6455 §4 needs roughly ten
/// observable header shapes; we parse those by hand (`~80 LOC byte
/// state machine`) rather than pulling in a full HTTP library. After
/// the `\r\n\r\n` boundary the same socket flips to WS frame
/// framing — the carrier transports both phases identically.
///
/// `wss://` plugs into the same architecture by polarising the
/// carrier scheme to `tls` when the URI's scheme is `wss`; framing,
/// handshake, send-queue, and close discipline stay byte-for-byte
/// identical because the carrier presents an opaque byte pipe in
/// both cases.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/uri.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::ws {

/// RFC 6455 §5.2 frame opcodes. Only the subset GoodNet uses is
/// enumerated; reserved opcodes flow through as a generic "other".
enum class Opcode : std::uint8_t {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
};

class WsLink : public std::enable_shared_from_this<WsLink> {
public:
    WsLink();
    ~WsLink();

    WsLink(const WsLink&)            = delete;
    WsLink& operator=(const WsLink&) = delete;

    /// Bind a listening WebSocket endpoint. URI form is
    /// `ws://host:port[/path]` per `uri.md`. The path component is
    /// accepted but not routed — every upgrade succeeds regardless
    /// of resource path; refining that requires an HTTP routing
    /// layer that v1 explicitly does not own.
    [[nodiscard]] gn_result_t listen(std::string_view uri);

    /// Initiate an outbound WebSocket connection. The L1 carrier
    /// connect plus the HTTP upgrade run on the carrier worker
    /// thread; the kernel learns of the established session through
    /// `notify_connect` only after the upgrade response parses
    /// successfully.
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    /// Send one application payload as a single binary frame
    /// (opcode 0x2). Frames larger than `kMaxFramePayload` are
    /// rejected — fragmentation across continuation frames is
    /// supported on the receive path but not produced on the send
    /// path because GoodNet's protocol layer already enforces a
    /// frame budget.
    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    /// Coalesce a scatter-gather batch into one binary frame; same
    /// invariants as `send`.
    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);

    /// Idempotent close. Sends a graceful close frame (opcode 0x8)
    /// before tearing down the underlying carrier conn.
    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;
    void shutdown();

    [[nodiscard]] std::uint16_t listen_port() const noexcept;
    [[nodiscard]] std::size_t   session_count() const noexcept;

    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

    /// Override the per-connection hard cap after `set_host_api` —
    /// the regression suite for `backpressure.md` §3.1 needs a tiny
    /// cap to exercise the control-reply abuse path inside a unit
    /// test. Production callers configure the cap through
    /// `gn_limits_t::pending_queue_bytes_hard`.
    void set_pending_queue_bytes_hard_for_test(std::uint64_t bytes) noexcept;

    /// Simulate a peer-initiated frame on @p conn by pushing @p bytes
    /// straight through the L1 carrier. The receive path of the peer's
    /// session parses and processes the frame as if it arrived over
    /// the wire. Used by the regression suite for `backpressure.md`
    /// §3.1.
    [[nodiscard]] gn_result_t send_raw_for_test(
        gn_conn_id_t conn,
        std::span<const std::uint8_t> bytes);

    /// RFC 6455 mandates a 64 KiB ceiling on a single frame's
    /// payload before the implementation should fall back to
    /// fragmentation. GoodNet caps below that so the receive buffer
    /// stays bounded; longer payloads need to be split at the
    /// protocol layer.
    static constexpr std::size_t kMaxFramePayload = 65536;

    /// Parsed `ws://host:port[/path]` or `wss://host:port[/path]`
    /// shape. Inherits `host`, `port`, `scheme`, `host_authority()`
    /// from `gn::UriParts` (no duplication); adds the WS-specific
    /// `path` (HTTP resource path, e.g. `/foo`) and `secure` flag.
    /// Public so the test suite can pin RFC 7230 §5.4 bracketing
    /// without spinning up a live socket.
    struct ParsedUri : public ::gn::UriParts {
        /// HTTP resource path. Defaults to `/` per browser fallback
        /// when the URI omits it. `UriParts::path` (parent) is the
        /// ipc-style path slot and stays empty for `ws://` / `wss://`.
        std::string http_path = "/";
        /// `true` for `wss://`, `false` for `ws://`. Slice 6 carrier
        /// polarisation reads this to choose between the
        /// `gn.link.tcp` and `gn.link.tls` L1 carriers. Could be
        /// derived from `scheme == "wss"` but kept as an explicit
        /// field so call sites don't repeat the string compare.
        bool secure = false;
    };
    [[nodiscard]] static std::optional<ParsedUri> parse_uri(
        std::string_view uri);

private:
    class Session;

    /// Trust class for an inbound peer URI as the carrier reports
    /// it. Loopback addresses surface as `Loopback`, everything
    /// else `Untrusted`. WSS upgrades the byte stream through TLS at
    /// the carrier layer; the upgrade above does not change the
    /// trust derived from the L4 address.
    [[nodiscard]] static gn_trust_class_t resolve_trust_from_uri(
        std::string_view peer_uri) noexcept;

    /// Convert a tcp/tls peer URI into the canonical ws/wss form so
    /// the kernel's connection record matches the configured scheme.
    [[nodiscard]] static std::string rewrite_peer_uri(
        std::string_view carrier_peer_uri, bool secure);

    /// Bind the carrier matching @p secure on demand. Returns the
    /// queried carrier scheme on success.
    [[nodiscard]] gn_result_t ensure_carrier(bool secure);

    void compose_server_session(gn_conn_id_t l1,
                                 std::string_view peer_uri);

    void register_session(gn_conn_id_t ws_id,
                           std::shared_ptr<Session> s);
    /// Atomic claim of a disconnect emission for @p ws_id. Mirrors the
    /// TcpLink discipline: the session callback wins claim race when
    /// `shutdown_` is unset, otherwise the caller-thread shutdown
    /// drain owns the emission.
    [[nodiscard]] bool claim_disconnect(gn_conn_id_t ws_id);
    /// Drop the L1 ↔ WS association regardless of phase. Called from
    /// session `fail()` paths so the next on_data lookup misses.
    void drop_l1_mapping(gn_conn_id_t l1);
    [[nodiscard]] std::shared_ptr<Session>
    find_session_by_ws(gn_conn_id_t ws_id) const;
    [[nodiscard]] std::shared_ptr<Session>
    find_session_by_l1(gn_conn_id_t l1) const;

    std::atomic<bool> shutdown_{false};

    mutable std::mutex sessions_mu_;
    /// L1 (carrier) conn id → Session. Populated from the moment a
    /// Session is created (handshake phase) until carrier disconnect.
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>> by_l1_;
    /// WS conn id (kernel-assigned via `notify_connect`) → Session.
    /// Populated only after the handshake completes successfully.
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>> by_ws_;

    /// Append-only record of every ws_id ever registered through
    /// `notify_connect`. `shutdown()` drains it through
    /// `notify_disconnect` on the caller thread so each
    /// `notify_connect` maps to exactly one caller-thread
    /// `notify_disconnect` even when a worker already emitted the
    /// release on its own thread (`link.md` §9 step 3).
    std::vector<gn_conn_id_t> published_ids_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection hard cap on outbound WS frame size — the
    /// `backpressure.md` §3.1 control-reply abuse protection. With the
    /// composer-mode refactor the WS layer no longer owns a write
    /// queue (the carrier does); we still bound a single emitted
    /// frame's size so a peer cannot drive arbitrarily large echoes.
    std::uint64_t pending_queue_bytes_hard_ = 0;

    const host_api_t* api_ = nullptr;

    /// L1 carrier handle, queried lazily on first listen / connect.
    /// The scheme is fixed for the lifetime of the handle: a WsLink
    /// instance speaks either ws-over-tcp or wss-over-tls, never both
    /// concurrently. Slice 6 picks the scheme at URI parse time.
    std::optional<gn::sdk::LinkCarrier> carrier_;
    bool carrier_secure_ = false;
};

} // namespace gn::link::ws
