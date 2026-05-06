// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws.hpp
/// @brief  RFC 6455 WebSocket transport (`ws://`).
///
/// Plain WebSocket only. `wss://` is the same WS framing over a
/// TLS-wrapped socket — once the `gn.link.tls` composer plugin
/// ships, `wss://` URIs route through `tls + ws` rather than
/// duplicating framing here. WS does not need its own security
/// layer: the kernel's identity / Noise pipeline lives above the
/// transport regardless of scheme.
///
/// Architecture mirrors TcpLink: own `asio::io_context` on a
/// dedicated worker thread, strand-per-session writes serialise the
/// single-writer invariant from `link.md` §4. The upgrade
/// handshake parses HTTP/1.1 by hand — RFC 6455 §4 specifies a
/// minimal subset: case-insensitive header names, `\r\n` line
/// terminators, and exactly one mandatory `Sec-WebSocket-Key` /
/// `Sec-WebSocket-Accept` exchange. We avoid pulling in a full HTTP
/// library because the message set has fewer than ten observable
/// shapes and a parser specialized to those is ~80 lines.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

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

    /// Initiate an outbound WebSocket connection. The TCP three-way
    /// handshake plus the HTTP upgrade run on the worker thread; the
    /// kernel learns of the established session through
    /// `notify_connect` only after the upgrade response is parsed
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
    /// before tearing down the TCP socket.
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

    /// Simulate a peer-initiated frame on @p conn by writing @p
    /// bytes directly through the session's socket on the worker
    /// strand. The receive path of the peer's session parses and
    /// processes the frame as if it arrived over the wire. Used by
    /// the regression suite for `backpressure.md` §3.1.
    [[nodiscard]] gn_result_t send_raw_for_test(
        gn_conn_id_t conn,
        std::span<const std::uint8_t> bytes);

    /// RFC 6455 mandates a 64 KiB ceiling on a single frame's
    /// payload before the implementation should fall back to
    /// fragmentation. GoodNet caps below that so the receive buffer
    /// stays bounded; longer payloads need to be split at the
    /// protocol layer.
    static constexpr std::size_t kMaxFramePayload = 65536;

    /// Parsed `ws://host:port[/path]` shape with a derived
    /// `host_authority()` for the HTTP upgrade `Host:` header.
    /// Public so the test suite can pin the bracket discipline
    /// (RFC 7230 §5.4) without spinning up a live socket.
    struct ParsedUri {
        std::string host;
        std::uint16_t port = 0;
        std::string  path = "/";

        /// `host:port` / `[v6]:port` form for the HTTP `Host:`
        /// header (RFC 7230 §5.4). Mirrors
        /// `gn::UriParts::host_authority`.
        [[nodiscard]] std::string host_authority() const {
            std::string s;
            const bool is_v6 = host.find(':') != std::string::npos;
            s.reserve(host.size() + 8);
            if (is_v6) s += '[';
            s += host;
            if (is_v6) s += ']';
            s += ':';
            s += std::to_string(port);
            return s;
        }
    };
    [[nodiscard]] static std::optional<ParsedUri> parse_uri(
        std::string_view uri);

private:
    class Session;

    /// Trust class derives from peer address: loopback addresses
    /// surface as `Loopback`, everything else `Untrusted`. WSS
    /// inherits the upgrade path through Noise.
    [[nodiscard]] static gn_trust_class_t resolve_trust(
        const asio::ip::tcp::endpoint& peer) noexcept;

    /// Re-arm the acceptor for the next inbound connection.
    void start_accept();
    void on_accept(std::shared_ptr<Session> session,
                    const std::error_code& ec);

    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    [[nodiscard]] static std::string endpoint_to_uri(
        const asio::ip::tcp::endpoint& ep, std::string_view path);

    asio::io_context                                                 ioc_;
    asio::executor_work_guard<asio::io_context::executor_type>       work_;
    std::thread                                                      worker_;

    std::optional<asio::ip::tcp::acceptor> acceptor_;
    std::atomic<std::uint16_t>             listen_port_{0};
    std::atomic<bool>                      shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.md`
    /// §1.
    std::uint64_t pending_queue_bytes_low_  = 0;
    std::uint64_t pending_queue_bytes_high_ = 0;
    std::uint64_t pending_queue_bytes_hard_ = 0;

    const host_api_t* api_ = nullptr;
};

} // namespace gn::link::ws
