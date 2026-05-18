// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws_session.hpp
/// @brief  `WsLink::Session` — RFC 6455 frame state machine running
///         over a `LinkCarrier` L1 (TCP / TLS). Split out of ws.cpp
///         so the WsLink top-level (URI parsing, carrier wiring,
///         session registry) and the per-conn frame pipeline evolve
///         in separate files — same split pattern as the TCP and
///         TLS plugins' composer sessions.
///
/// Header-only: the methods are short or mutually recursive enough
/// that the compiler benefits from inlining (the WS hot path is
/// `feed_inbound → dispatch_frames → notify_inbound_bytes`).
/// Splitting into a separate .cpp would carry no runtime gain and
/// duplicate the include preamble across two TUs.

#pragma once

#include "ws.hpp"

#include "wire.hpp"
#include "ws_http_parse.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/link_carrier.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace gn::link::ws {

/// Generate 16 random bytes, base64-encode → `Sec-WebSocket-Key` per
/// RFC 6455 §1.3. The bytes are not security-sensitive (the kernel's
/// identity / Noise layer above does that work); a thread-local
/// Mersenne-Twister suffices for uniqueness across outstanding
/// outbound connections.
inline std::string make_sec_websocket_key() {
    thread_local std::mt19937 rng{std::random_device{}()};
    std::array<std::uint8_t, 16> bytes{};
    for (auto& b : bytes) b = static_cast<std::uint8_t>(rng());
    return wire::base64_encode(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

/// 32-bit random seed for masking. Same rationale: not security
/// critical, the kernel encrypts above us.
inline std::uint32_t make_mask_seed() {
    thread_local std::mt19937 rng{std::random_device{}()};
    return static_cast<std::uint32_t>(rng());
}

inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/// Per-connection state: holds the WS handshake / frame parsing
/// state, dispatches application bytes to the kernel through
/// `notify_inbound_bytes`, and serialises outbound frames via the
/// parent `WsLink`'s L1 carrier. The carrier guarantees per-L1
/// strand serialisation of `on_data` callbacks, so Session-internal
/// state mutates from one thread at a time (no Session-local
/// strand needed any more).
class WsLink::Session : public std::enable_shared_from_this<Session> {
public:
    enum class Mode  { Server, Client };
    enum class Phase { Handshake, Frames, Closed };

    Session(std::weak_ptr<WsLink> transport,
            gn_conn_id_t l1_id,
            Mode mode)
        : transport_(std::move(transport)),
          l1_id_(l1_id),
          mode_(mode) {}

    [[nodiscard]] gn_conn_id_t l1_id() const noexcept { return l1_id_; }
    [[nodiscard]] gn_conn_id_t conn_id() const noexcept { return conn_id_; }
    [[nodiscard]] Mode mode() const noexcept { return mode_; }
    [[nodiscard]] Phase phase() const noexcept { return phase_; }

    /// Build and emit the HTTP/1.1 upgrade request through the
    /// carrier. Called once after `WsLink::connect` finishes the
    /// L1 connect. The server reply will arrive through
    /// `feed_inbound` and drive the transition to Phase::Frames.
    void start_client_handshake(const std::string& host_header,
                                 const std::string& path) {
        phase_ = Phase::Handshake;
        nonce_ = make_sec_websocket_key();
        /// HTTP request-line injection gate. The path is interpolated
        /// verbatim into `GET <path> HTTP/1.1\r\n`; a path containing
        /// CR / LF / NUL would let an attacker terminate the request
        /// line early and smuggle additional headers — the classic
        /// HTTP request-smuggling shape on a WebSocket upgrade.
        /// Reject and fail before writing any bytes.
        for (const char c : path) {
            if (c == '\r' || c == '\n' || c == '\0') {
                fail();
                return;
            }
        }
        for (const char c : host_header) {
            if (c == '\r' || c == '\n' || c == '\0') {
                fail();
                return;
            }
        }
        std::ostringstream req;
        req << "GET " << path << " HTTP/1.1\r\n"
            << "Host: " << host_header << "\r\n"
            << "Upgrade: websocket\r\n"
            << "Connection: Upgrade\r\n"
            << "Sec-WebSocket-Key: " << nonce_ << "\r\n"
            << "Sec-WebSocket-Version: 13\r\n\r\n";
        const std::string s = req.str();
        if (!send_through_carrier(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(s.data()),
                s.size()))) {
            fail();
        }
    }

    /// Receive callback target — bytes arrive from the L1 carrier
    /// for this session's `l1_id_`. Called from the carrier's
    /// per-conn strand, so Session-internal state is single-threaded
    /// per Session instance.
    void feed_inbound(std::span<const std::uint8_t> bytes) {
        if (phase_ == Phase::Closed) return;
        auto t = transport_.lock();
        if (!t) return;
        t->bytes_in_.fetch_add(bytes.size(), std::memory_order_relaxed);

        if (phase_ == Phase::Handshake) {
            handshake_buf_.append(
                reinterpret_cast<const char*>(bytes.data()),
                bytes.size());
            /// Cap to avoid a peer feeding us megabytes of header
            /// lines; 8 KiB is the de facto HTTP header budget.
            if (handshake_buf_.size() > 8192) {
                fail();
                return;
            }
            const auto sep = handshake_buf_.find("\r\n\r\n");
            if (sep == std::string::npos) return;
            /// Any bytes past the upgrade terminator are already WS
            /// frame data — carry them over into `frame_buf_`.
            const auto trailing_start = sep + 4;
            if (trailing_start < handshake_buf_.size()) {
                frame_buf_.insert(
                    frame_buf_.end(),
                    reinterpret_cast<const std::uint8_t*>(
                        handshake_buf_.data() + trailing_start),
                    reinterpret_cast<const std::uint8_t*>(
                        handshake_buf_.data() + handshake_buf_.size()));
            }
            const auto upgrade_view =
                std::string_view(handshake_buf_).substr(0, trailing_start);
            if (mode_ == Mode::Server) {
                finish_server_handshake(upgrade_view);
            } else {
                finish_client_handshake(upgrade_view);
            }
            handshake_buf_.clear();
            if (phase_ != Phase::Frames) return;
            /// Any frame bytes that came in the same TCP read need to
            /// be dispatched now — they will not retrigger on_data.
            if (!frame_buf_.empty()) dispatch_frames();
            return;
        }

        frame_buf_.insert(frame_buf_.end(), bytes.begin(), bytes.end());
        dispatch_frames();
    }

    /// Enqueue one application payload as a single binary frame.
    /// The hard-cap check happens before framing so the size against
    /// the cap mirrors what actually goes onto the wire.
    [[nodiscard]] gn_result_t enqueue_send(
        std::span<const std::uint8_t> payload) {
        auto t = transport_.lock();
        if (!t) return GN_ERR_NOT_FOUND;
        if (phase_ == Phase::Closed) return GN_ERR_NOT_FOUND;
        auto frame = wire::build_binary_frame(payload,
            /*mask=*/mode_ == Mode::Client,
            make_mask_seed());
        if (t->pending_queue_bytes_hard_ != 0 &&
            frame.size() > t->pending_queue_bytes_hard_) {
            if (t->api_) {
                if (t->api_->emit_counter) {
                    t->api_->emit_counter(t->api_->host_ctx,
                                          "drop.queue_hard_cap");
                }
                gn_log_warn(t->api_,
                    "ws.send: queue hard cap — conn=%llu frame=%zu hard=%zu",
                    static_cast<unsigned long long>(conn_id_),
                    frame.size(),
                    static_cast<std::size_t>(t->pending_queue_bytes_hard_));
            }
            return GN_ERR_LIMIT_REACHED;
        }
        if (!send_through_carrier(
                std::span<const std::uint8_t>(frame.data(), frame.size()))) {
            return GN_ERR_NOT_FOUND;
        }
        t->frames_out_.fetch_add(1, std::memory_order_relaxed);
        t->bytes_out_.fetch_add(frame.size(), std::memory_order_relaxed);
        return GN_OK;
    }

    /// Bypass framing — push raw bytes through the carrier as-is.
    /// Used only by the test harness for `backpressure.en.md` §3.1.
    [[nodiscard]] gn_result_t send_raw(
        std::span<const std::uint8_t> bytes) {
        if (phase_ == Phase::Closed) return GN_ERR_NOT_FOUND;
        if (!send_through_carrier(bytes)) return GN_ERR_NOT_FOUND;
        return GN_OK;
    }

    /// Idempotent close: best-effort emit a WS close frame, then ask
    /// the carrier to tear down the L1 conn. Subsequent feed_inbound
    /// short-circuits because phase_ is Closed.
    void enqueue_close() {
        if (phase_ == Phase::Closed) return;
        phase_ = Phase::Closed;
        auto t = transport_.lock();
        if (!t) return;
        auto frame = wire::build_close_frame(
            mode_ == Mode::Client, make_mask_seed());
        /// Per backpressure.en.md §3.1: a queued close frame past the
        /// per-conn hard cap is dropped; the carrier disconnect below
        /// still carries the closure regardless of whether the wire-
        /// level frame went out.
        if (t->pending_queue_bytes_hard_ == 0 ||
            frame.size() <= t->pending_queue_bytes_hard_) {
            (void)send_through_carrier(
                std::span<const std::uint8_t>(frame.data(), frame.size()));
            t->frames_out_.fetch_add(1, std::memory_order_relaxed);
            t->bytes_out_.fetch_add(frame.size(),
                                     std::memory_order_relaxed);
        }
        if (t->carrier_) {
            (void)t->carrier_->disconnect(l1_id_);
        }
    }

    void set_conn_id(gn_conn_id_t id) noexcept { conn_id_ = id; }

private:
    void finish_server_handshake(std::string_view upgrade) {
        auto req = parse_http_request(upgrade);
        if (!req || req->method != "GET") { fail(); return; }
        const auto find = [&](std::string_view name)
            -> const std::string* {
            auto it = req->headers.find(std::string{name});
            return it == req->headers.end() ? nullptr : &it->second;
        };
        const auto upgrade_h   = find("upgrade");
        const auto connection  = find("connection");
        const auto key         = find("sec-websocket-key");
        const auto version     = find("sec-websocket-version");
        if (!upgrade_h || !connection || !key || !version) { fail(); return; }
        if (!iequals(*upgrade_h, "websocket"))             { fail(); return; }
        if (connection->find("Upgrade") == std::string::npos &&
            connection->find("upgrade") == std::string::npos) {
            fail(); return;
        }
        if (*version != "13") { fail(); return; }

        const auto accept_value = wire::handshake_accept(*key);
        std::ostringstream resp;
        resp << "HTTP/1.1 101 Switching Protocols\r\n"
             << "Upgrade: websocket\r\n"
             << "Connection: Upgrade\r\n"
             << "Sec-WebSocket-Accept: " << accept_value << "\r\n\r\n";
        const std::string s = resp.str();
        if (!send_through_carrier(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(s.data()),
                s.size()))) {
            fail(); return;
        }
        open_session(GN_ROLE_RESPONDER);
    }

    void finish_client_handshake(std::string_view upgrade) {
        auto resp = parse_http_response(upgrade);
        if (!resp || resp->status != 101) { fail(); return; }
        auto it = resp->headers.find("sec-websocket-accept");
        if (it == resp->headers.end()) { fail(); return; }
        if (it->second != wire::handshake_accept(nonce_)) {
            fail(); return;
        }
        open_session(GN_ROLE_INITIATOR);
    }

    void open_session(gn_handshake_role_t role) {
        auto t = transport_.lock();
        if (!t) { fail(); return; }
        if (!t->api_ || !t->api_->notify_connect) { fail(); return; }

        gn_conn_id_t id = GN_INVALID_ID;
        const auto peer_uri = peer_uri_;  // copied during compose
        if (t->api_->notify_connect(t->api_->host_ctx,
                                     /*remote_pk=*/nullptr,
                                     peer_uri.c_str(),
                                     trust_,
                                     role, &id) != GN_OK) {
            fail();
            return;
        }
        conn_id_ = id;
        t->register_session(id, shared_from_this());

        if (role == GN_ROLE_INITIATOR && t->api_->kick_handshake) {
            (void)t->api_->kick_handshake(t->api_->host_ctx, id);
        }
        phase_ = Phase::Frames;
    }

    void dispatch_frames() {
        while (true) {
            auto header = wire::parse_frame_header(
                std::span<const std::uint8_t>(
                    frame_buf_.data(), frame_buf_.size()));
            if (!header) return;
            const std::size_t total = header->header_size + header->payload_len;
            if (frame_buf_.size() < total) return;

            const auto hdr_ofs =
                static_cast<std::ptrdiff_t>(header->header_size);
            const auto total_ofs = static_cast<std::ptrdiff_t>(total);
            std::vector<std::uint8_t> payload(
                frame_buf_.begin() + hdr_ofs,
                frame_buf_.begin() + total_ofs);
            frame_buf_.erase(frame_buf_.begin(),
                              frame_buf_.begin() + total_ofs);

            /// Server-from-client frames MUST be masked; client-from
            /// -server frames MUST NOT be (RFC 6455 §5.1). Either
            /// violation is a protocol error.
            if (mode_ == Mode::Server && !header->masked) {
                fail(); return;
            }
            if (mode_ == Mode::Client &&  header->masked) {
                fail(); return;
            }
            if (header->masked) {
                wire::apply_mask(
                    std::span<std::uint8_t>(payload.data(), payload.size()),
                    header->mask);
            }

            auto t = transport_.lock();
            if (!t) return;
            t->frames_in_.fetch_add(1, std::memory_order_relaxed);

            switch (header->opcode) {
                case 0x0:  // continuation
                case 0x1:  // text — treated as binary at the byte level
                case 0x2:  // binary
                    if (!header->fin) {
                        /// Fragmented WS messages are out of scope —
                        /// the kernel's protocol layer caps frames
                        /// anyway, so legitimate peers stay under
                        /// one frame. Fragment support is a planned
                        /// extension.
                        fail();
                        return;
                    }
                    if (t->api_ && t->api_->notify_inbound_bytes) {
                        const gn_result_t rc =
                            t->api_->notify_inbound_bytes(
                                t->api_->host_ctx, conn_id_,
                                payload.data(), payload.size());
                        if (rc == GN_OK) {
                            host_api_failures_.store(
                                0, std::memory_order_relaxed);
                        } else if (rc == GN_ERR_LIMIT_REACHED) {
                            /// Receiver-side backpressure — kernel
                            /// session's recv buffer momentarily full.
                            /// LIMIT_REACHED stays excluded from the
                            /// 16-failure disconnect counter (treated
                            /// as transient). The full stalled-recv
                            /// park that TCP / IPC / TLS carry does
                            /// not map cleanly here — WS dispatches
                            /// inside the carrier's callback without
                            /// its own strand, so retry plumbing
                            /// would have to thread through carrier
                            /// pause / resume semantics. The carrier
                            /// underneath (TCP or TLS via the IPC
                            /// stalled-recv park) already absorbs the
                            /// transient stall; a future WS-level
                            /// park that survives multi-frame stalls
                            /// remains an open extension.
                            host_api_failures_.store(
                                0, std::memory_order_relaxed);
                        } else {
                            const auto fails =
                                host_api_failures_.fetch_add(
                                    1, std::memory_order_relaxed) + 1;
                            if (fails >= 16) {
                                fail();
                                return;
                            }
                        }
                    }
                    break;
                case 0x8: {  // close
                    /// Mirror back, then tear down. Idempotent if we
                    /// already initiated close.
                    if (phase_ == Phase::Frames) {
                        const auto reply = wire::build_close_frame(
                            mode_ == Mode::Client, make_mask_seed());
                        if (t->pending_queue_bytes_hard_ == 0 ||
                            reply.size() <=
                                t->pending_queue_bytes_hard_) {
                            (void)send_through_carrier(
                                std::span<const std::uint8_t>(
                                    reply.data(), reply.size()));
                            t->frames_out_.fetch_add(
                                1, std::memory_order_relaxed);
                            t->bytes_out_.fetch_add(
                                reply.size(),
                                std::memory_order_relaxed);
                        }
                    }
                    phase_ = Phase::Closed;
                    if (t->carrier_) {
                        (void)t->carrier_->disconnect(l1_id_);
                    }
                    return;
                }
                case 0x9: {  // ping
                    auto pong = wire::build_pong_frame(
                        std::span<const std::uint8_t>(
                            payload.data(), payload.size()),
                        mode_ == Mode::Client, make_mask_seed());
                    /// Per backpressure.en.md §3.1: a control flood is
                    /// abuse, not production traffic. If echoing the
                    /// pong would push beyond the per-frame hard cap,
                    /// disconnect rather than amplify the buffer.
                    if (t->pending_queue_bytes_hard_ != 0 &&
                        pong.size() > t->pending_queue_bytes_hard_) {
                        fail();
                        return;
                    }
                    (void)send_through_carrier(
                        std::span<const std::uint8_t>(
                            pong.data(), pong.size()));
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    t->bytes_out_.fetch_add(pong.size(),
                                             std::memory_order_relaxed);
                    break;
                }
                case 0xA:  // pong — no kernel signal
                    break;
                default:
                    fail();
                    return;
            }
        }
    }

    bool send_through_carrier(std::span<const std::uint8_t> bytes) {
        auto t = transport_.lock();
        if (!t || !t->carrier_) return false;
        return t->carrier_->send(l1_id_, bytes) == GN_OK;
    }

    void fail() {
        if (phase_ == Phase::Closed) return;
        phase_ = Phase::Closed;
        auto t = transport_.lock();
        if (!t) return;
        if (t->carrier_) {
            (void)t->carrier_->disconnect(l1_id_);
        }
        if (conn_id_ != GN_INVALID_ID && t->claim_disconnect(conn_id_) &&
            t->api_ && t->api_->notify_disconnect) {
            t->api_->notify_disconnect(
                t->api_->host_ctx, conn_id_, GN_OK);
        }
        t->drop_l1_mapping(l1_id_);
    }

public:
    /// Stamped by `compose_server_session` / `connect` before the
    /// upgrade completes — used at `notify_connect` time so the
    /// kernel record matches the canonical scheme.
    std::string         peer_uri_;
    gn_trust_class_t    trust_ = GN_TRUST_UNTRUSTED;

private:
    std::weak_ptr<WsLink>     transport_;
    gn_conn_id_t              l1_id_   = GN_INVALID_ID;
    Mode                      mode_    = Mode::Server;
    Phase                     phase_   = Phase::Handshake;
    gn_conn_id_t              conn_id_ = GN_INVALID_ID;
    std::string               handshake_buf_;
    std::vector<std::uint8_t> frame_buf_;
    std::string               nonce_;
    std::atomic<std::uint32_t> host_api_failures_{0};
};

}  // namespace gn::link::ws
