// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws.cpp
/// @brief  Implementation of the RFC 6455 WebSocket transport.

#include "ws.hpp"

#include "wire.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/connect.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <deque>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace gn::link::ws {

namespace {

/// Generate 16 random bytes, base64-encode → `Sec-WebSocket-Key`
/// per RFC 6455 §1.3. The bytes are not security-sensitive (the
/// kernel's identity / Noise layer above does that work); a
/// thread-local Mersenne-Twister suffices for uniqueness across
/// outstanding outbound connections.
std::string make_sec_websocket_key() {
    thread_local std::mt19937 rng{std::random_device{}()};
    std::array<std::uint8_t, 16> bytes{};
    for (auto& b : bytes) b = static_cast<std::uint8_t>(rng());
    return wire::base64_encode(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

/// 32-bit random seed for masking. Same rationale: not security
/// critical, the kernel encrypts above us.
std::uint32_t make_mask_seed() {
    thread_local std::mt19937 rng{std::random_device{}()};
    return static_cast<std::uint32_t>(rng());
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

struct ParsedRequest {
    std::string method;
    std::string target;
    std::unordered_map<std::string, std::string> headers;
};

std::optional<ParsedRequest> parse_http_request(std::string_view raw) {
    /// Walk the buffer line by line, consuming up to "\r\n\r\n".
    /// The minimum a valid WS upgrade carries is request-line +
    /// `Host:` + `Upgrade: websocket` + `Connection: Upgrade` +
    /// `Sec-WebSocket-Key:` + `Sec-WebSocket-Version: 13`. We
    /// accept any header order.
    ParsedRequest pr;
    std::size_t pos = 0;
    auto next_line = [&]() -> std::optional<std::string_view> {
        const auto crlf = raw.find("\r\n", pos);
        if (crlf == std::string_view::npos) return std::nullopt;
        const auto line = raw.substr(pos, crlf - pos);
        pos = crlf + 2;
        return line;
    };

    auto request_line = next_line();
    if (!request_line) return std::nullopt;
    auto sp1 = request_line->find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    auto sp2 = request_line->find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return std::nullopt;
    pr.method = std::string{request_line->substr(0, sp1)};
    pr.target = std::string{request_line->substr(sp1 + 1, sp2 - sp1 - 1)};

    while (true) {
        auto line = next_line();
        if (!line) return std::nullopt;
        if (line->empty()) break;
        const auto colon = line->find(':');
        if (colon == std::string_view::npos) continue;
        std::string name{trim(line->substr(0, colon))};
        std::string value{trim(line->substr(colon + 1))};
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char ch) { return std::tolower(ch); });
        pr.headers[std::move(name)] = std::move(value);
    }
    return pr;
}

struct ParsedResponse {
    int status = 0;
    std::unordered_map<std::string, std::string> headers;
};

std::optional<ParsedResponse> parse_http_response(std::string_view raw) {
    ParsedResponse pr;
    std::size_t pos = 0;
    auto next_line = [&]() -> std::optional<std::string_view> {
        const auto crlf = raw.find("\r\n", pos);
        if (crlf == std::string_view::npos) return std::nullopt;
        const auto line = raw.substr(pos, crlf - pos);
        pos = crlf + 2;
        return line;
    };

    auto status_line = next_line();
    if (!status_line) return std::nullopt;
    /// "HTTP/1.1 101 Switching Protocols"
    auto sp1 = status_line->find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    auto sp2 = status_line->find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return std::nullopt;
    const auto code_sv = status_line->substr(sp1 + 1, sp2 - sp1 - 1);
    pr.status = 0;
    for (auto ch : code_sv) {
        if (ch < '0' || ch > '9') return std::nullopt;
        pr.status = pr.status * 10 + (ch - '0');
    }

    while (true) {
        auto line = next_line();
        if (!line) return std::nullopt;
        if (line->empty()) break;
        const auto colon = line->find(':');
        if (colon == std::string_view::npos) continue;
        std::string name{trim(line->substr(0, colon))};
        std::string value{trim(line->substr(colon + 1))};
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char ch) { return std::tolower(ch); });
        pr.headers[std::move(name)] = std::move(value);
    }
    return pr;
}

} // namespace

// ── Session ──────────────────────────────────────────────────────────────

class WsLink::Session : public std::enable_shared_from_this<Session> {
public:
    enum class Mode { Server, Client };
    enum class Phase { Handshake, Frames, Closed };

    Session(asio::ip::tcp::socket sock,
            std::weak_ptr<WsLink> t,
            Mode mode)
        : socket_(std::move(sock)),
          strand_(asio::make_strand(socket_.get_executor())),
          transport_(std::move(t)),
          mode_(mode) {}

    void start_server_handshake() {
        phase_ = Phase::Handshake;
        do_read_handshake();
    }

    void start_client_handshake(const std::string& host_header,
                                 const std::string& path) {
        phase_      = Phase::Handshake;
        nonce_      = make_sec_websocket_key();
        /// HTTP request-line injection gate. The path is interpolated
        /// verbatim into `GET <path> HTTP/1.1\r\n`; a path containing
        /// CR / LF / NUL would let an attacker terminate the
        /// request line early and smuggle additional headers — the
        /// classic HTTP request-smuggling shape on a WebSocket
        /// upgrade. Reject and fail before writing any bytes.
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
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            s.begin(), s.end());
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf](
                    const std::error_code& ec, std::size_t) {
                    if (ec) {
                        self->fail();
                        return;
                    }
                    self->do_read_handshake();
                }));
    }

    void enqueue_send(std::span<const std::uint8_t> payload) {
        auto frame = std::make_shared<std::vector<std::uint8_t>>(
            wire::build_binary_frame(payload,
                /*mask=*/mode_ == Mode::Client,
                make_mask_seed()));
        const auto added = frame->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), frame]() mutable {
                self->write_queue_.push_back(std::move(frame));
                self->maybe_start_write();
            });
    }

    [[nodiscard]] std::uint64_t bytes_buffered() const noexcept {
        return bytes_buffered_.load(std::memory_order_relaxed);
    }

    void maybe_signal_soft(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_high_ == 0) return;
        if (post <= t->pending_queue_bytes_high_) return;
        bool expected = false;
        if (!soft_signaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id_,
                GN_CONN_EVENT_BACKPRESSURE_SOFT, post);
        }
    }
    void maybe_signal_clear(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_low_ == 0) return;
        if (post >= t->pending_queue_bytes_low_) return;
        bool expected = true;
        if (!soft_signaled_.compare_exchange_strong(
                expected, false, std::memory_order_acq_rel)) {
            return;
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id_,
                GN_CONN_EVENT_BACKPRESSURE_CLEAR, post);
        }
    }

    /// Test-only: write @p data straight onto the wire as if the
    /// peer had emitted those bytes. The receive path on the other
    /// end parses the bytes through the normal frame loop. Used by
    /// the regression suite for `backpressure.md` §3.1; production
    /// code never invokes this.
    void send_raw_for_test(
        const std::shared_ptr<std::vector<std::uint8_t>>& data) {
        asio::async_write(socket_, asio::buffer(*data),
            asio::bind_executor(strand_,
                [self = shared_from_this(), data](
                    const std::error_code&, std::size_t) {
                    /// Test-only path; errors do not propagate.
                }));
    }

    void enqueue_close() {
        auto frame = std::make_shared<std::vector<std::uint8_t>>(
            wire::build_close_frame(/*mask=*/mode_ == Mode::Client,
                                    make_mask_seed()));
        asio::dispatch(strand_,
            [self = shared_from_this(), frame]() mutable {
                if (self->phase_ == Phase::Closed) return;
                /// Per backpressure.md §3.1: host-initiated close
                /// frames follow the same drop-on-overflow rule as
                /// peer-echoed close frames. The socket teardown
                /// below carries the closure regardless of whether
                /// the wire-level frame went out.
                auto t = self->transport_.lock();
                const auto hard_cap =
                    t ? t->pending_queue_bytes_hard_ : 0U;
                const auto current = self->bytes_buffered_.load(
                    std::memory_order_relaxed);
                if (hard_cap == 0 ||
                    current + frame->size() <= hard_cap) {
                    self->bytes_buffered_.fetch_add(
                        frame->size(), std::memory_order_relaxed);
                    self->write_queue_.push_back(std::move(frame));
                    self->maybe_start_write();
                }
                self->phase_ = Phase::Closed;
                std::error_code ec;
                if (self->socket_.shutdown(
                        asio::ip::tcp::socket::shutdown_send, ec)) {}
            });
    }

    void set_conn_id(gn_conn_id_t id) { conn_id_ = id; }
    [[nodiscard]] gn_conn_id_t conn_id() const noexcept { return conn_id_; }
    [[nodiscard]] asio::ip::tcp::socket& socket() noexcept { return socket_; }

private:
    void do_read_handshake() {
        socket_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    if (ec) { self->fail(); return; }
                    self->handshake_buf_.append(
                        reinterpret_cast<const char*>(self->read_buf_.data()),
                        n);
                    /// Cap to avoid a peer feeding us megabytes of
                    /// header lines; 8 KiB is the de facto HTTP
                    /// header budget.
                    if (self->handshake_buf_.size() > 8192) {
                        self->fail();
                        return;
                    }
                    if (self->handshake_buf_.find("\r\n\r\n") ==
                        std::string::npos) {
                        self->do_read_handshake();
                        return;
                    }
                    if (self->mode_ == Mode::Server) {
                        self->finish_server_handshake();
                    } else {
                        self->finish_client_handshake();
                    }
                }));
    }

    void finish_server_handshake() {
        auto req = parse_http_request(handshake_buf_);
        if (!req || req->method != "GET") { fail(); return; }
        const auto find = [&](std::string_view name) -> const std::string* {
            auto it = req->headers.find(std::string{name});
            return it == req->headers.end() ? nullptr : &it->second;
        };
        const auto upgrade    = find("upgrade");
        const auto connection = find("connection");
        const auto key        = find("sec-websocket-key");
        const auto version    = find("sec-websocket-version");
        if (!upgrade || !connection || !key || !version) { fail(); return; }
        if (!iequals(*upgrade, "websocket"))           { fail(); return; }
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
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            s.begin(), s.end());
        handshake_buf_.clear();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf](
                    const std::error_code& ec, std::size_t) {
                    if (ec) { self->fail(); return; }
                    self->open_session(GN_ROLE_RESPONDER);
                }));
    }

    void finish_client_handshake() {
        auto resp = parse_http_response(handshake_buf_);
        if (!resp || resp->status != 101) { fail(); return; }
        auto it = resp->headers.find("sec-websocket-accept");
        if (it == resp->headers.end()) { fail(); return; }
        if (it->second != wire::handshake_accept(nonce_)) { fail(); return; }
        handshake_buf_.clear();
        open_session(GN_ROLE_INITIATOR);
    }

    void open_session(gn_handshake_role_t role) {
        auto t = transport_.lock();
        if (!t) { fail(); return; }

        if (!t->api_ || !t->api_->notify_connect) {
            fail();
            return;
        }

        const auto peer = socket_.remote_endpoint();
        const auto trust = WsLink::resolve_trust(peer);
        const auto uri = WsLink::endpoint_to_uri(peer, "/");
        gn_conn_id_t id = GN_INVALID_ID;
        if (t->api_->notify_connect(t->api_->host_ctx,
                                     /*remote_pk=*/nullptr,
                                     uri.c_str(),
                                     trust, role, &id) != GN_OK) {
            fail();
            return;
        }
        conn_id_ = id;
        t->register_session(id, shared_from_this());

        if (role == GN_ROLE_INITIATOR && t->api_->kick_handshake) {
            (void)t->api_->kick_handshake(t->api_->host_ctx, id);
        }

        phase_ = Phase::Frames;
        do_read_frame();
    }

    void do_read_frame() {
        socket_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    if (ec) { self->fail(); return; }
                    auto t = self->transport_.lock();
                    if (!t) return;
                    t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                    self->frame_buf_.insert(self->frame_buf_.end(),
                        self->read_buf_.data(),
                        self->read_buf_.data() + n);
                    self->dispatch_frames();
                    if (self->phase_ != Phase::Closed) {
                        self->do_read_frame();
                    }
                }));
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
            if (mode_ == Mode::Server && !header->masked) { fail(); return; }
            if (mode_ == Mode::Client &&  header->masked) { fail(); return; }
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
                        /// Defer fragmented messages until v1.1; the
                        /// kernel's protocol layer caps frames anyway
                        /// so legitimate peers stay under one frame.
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
                        auto reply = std::make_shared<std::vector<std::uint8_t>>(
                            wire::build_close_frame(
                                mode_ == Mode::Client, make_mask_seed()));
                        /// Per backpressure.md §3.1: control replies
                        /// share the per-connection hard cap. If the
                        /// queue is already at the cap when the peer
                        /// asks to close, drop the echo — the socket
                        /// teardown below carries the closure signal
                        /// regardless.
                        const auto hard_cap = t->pending_queue_bytes_hard_;
                        const auto current = bytes_buffered_.load(
                            std::memory_order_relaxed);
                        if (hard_cap == 0 ||
                            current + reply->size() <= hard_cap) {
                            bytes_buffered_.fetch_add(
                                reply->size(), std::memory_order_relaxed);
                            write_queue_.push_back(std::move(reply));
                            maybe_start_write();
                        }
                    }
                    phase_ = Phase::Closed;
                    return;
                }
                case 0x9: {  // ping
                    auto pong = std::make_shared<std::vector<std::uint8_t>>(
                        wire::build_pong_frame(
                            std::span<const std::uint8_t>(
                                payload.data(), payload.size()),
                            mode_ == Mode::Client, make_mask_seed()));
                    /// Per backpressure.md §3.1: a control flood is
                    /// abuse, not production traffic. If echoing the
                    /// pong would push the queue past the hard cap,
                    /// disconnect rather than amplify the buffer.
                    const auto hard_cap = t->pending_queue_bytes_hard_;
                    const auto current = bytes_buffered_.load(
                        std::memory_order_relaxed);
                    if (hard_cap != 0 &&
                        current + pong->size() > hard_cap) {
                        fail();
                        return;
                    }
                    bytes_buffered_.fetch_add(
                        pong->size(), std::memory_order_relaxed);
                    write_queue_.push_back(std::move(pong));
                    maybe_start_write();
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

    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        const std::size_t buf_size = buf->size();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf, buf_size](
                    const std::error_code& ec, std::size_t n) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    const auto post = self->bytes_buffered_.fetch_sub(
                        buf_size, std::memory_order_relaxed) - buf_size;
                    self->maybe_signal_clear(post);
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) { self->fail(); return; }
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    /// Count the frame emission, not every chunk.
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    void fail() {
        if (phase_ == Phase::Closed) return;
        phase_ = Phase::Closed;
        std::error_code ec;
        if (socket_.close(ec)) {}
        if (auto t = transport_.lock()) {
            if (t->api_ && t->api_->notify_disconnect &&
                conn_id_ != GN_INVALID_ID) {
                t->api_->notify_disconnect(
                    t->api_->host_ctx, conn_id_, GN_OK);
            }
            if (conn_id_ != GN_INVALID_ID) {
                t->erase_session(conn_id_);
            }
        }
    }

    asio::ip::tcp::socket                              socket_;
    asio::strand<asio::any_io_executor>                strand_;
    std::weak_ptr<WsLink>                        transport_;
    Mode                                                mode_;
    Phase                                               phase_ = Phase::Handshake;

    gn_conn_id_t                                        conn_id_ = GN_INVALID_ID;
    std::array<std::uint8_t, 4096>                      read_buf_{};
    std::string                                         handshake_buf_;
    std::vector<std::uint8_t>                           frame_buf_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> write_queue_;
    bool                                                write_in_flight_ = false;
    std::atomic<std::uint64_t>                          bytes_buffered_{0};
    std::atomic<bool>                                   soft_signaled_{false};
    std::string                                         nonce_;
    /// Consecutive non-OK results from `notify_inbound_bytes`;
    /// 16 in a row triggers `fail()` so a peer that floods the
    /// security layer with garbage cannot keep the conn alive.
    std::atomic<std::uint32_t>                          host_api_failures_{0};
};

// ── WsLink ───────────────────────────────────────────────────────────────

WsLink::WsLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
}

WsLink::~WsLink() {
    /// The dtor must stay noexcept. `shutdown()` walks the strand
    /// dispatch chain, which can throw `bad_executor` once the
    /// io_context has torn down; surface through the host log if
    /// available, otherwise drop on the floor.
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "ws: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_, "ws: shutdown threw non-std exception");
        }
    }
    /// `shutdown()` joins the worker on every call where the
    /// caller is not the worker thread itself. A still-joinable
    /// worker here means the dtor itself ran on the worker — an
    /// ownership cycle in the caller (an async session handler is
    /// holding the last `shared_ptr<WsLink>`). `ioc_.stop()` from
    /// the shutdown call has already been issued so the worker is
    /// on its way to exit; detach lets the dtor stay noexcept and
    /// surfaces the violation through the host log for the caller
    /// to fix.
    if (worker_.joinable()) {
        if (api_) {
            gn_log_warn(api_,
                "ws: dtor reached on worker thread "
                "(ownership cycle in caller); detaching");
        }
        worker_.detach();
    }
}

void WsLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    if (api_ != nullptr && api_->limits != nullptr) {
        if (const auto* L = api_->limits(api_->host_ctx); L != nullptr) {
            pending_queue_bytes_low_  = L->pending_queue_bytes_low;
            pending_queue_bytes_high_ = L->pending_queue_bytes_high;
            pending_queue_bytes_hard_ = L->pending_queue_bytes_hard;
        }
    }
}

void WsLink::set_pending_queue_bytes_hard_for_test(
    std::uint64_t bytes) noexcept {
    pending_queue_bytes_hard_ = bytes;
}

gn_result_t WsLink::send_raw_for_test(
    gn_conn_id_t conn,
    std::span<const std::uint8_t> bytes) {
    auto s = find_session(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    auto data = std::make_shared<std::vector<std::uint8_t>>(
        bytes.begin(), bytes.end());
    s->send_raw_for_test(data);
    return GN_OK;
}

std::uint16_t WsLink::listen_port() const noexcept {
    return listen_port_.load(std::memory_order_acquire);
}

std::size_t WsLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

WsLink::Stats WsLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t WsLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_STREAM
                  | GN_LINK_CAP_RELIABLE
                  | GN_LINK_CAP_ORDERED;
    c.max_payload = static_cast<std::uint32_t>(kMaxFramePayload);
    return c;
}

gn_trust_class_t WsLink::resolve_trust(
    const asio::ip::tcp::endpoint& peer) noexcept {
    if (peer.address().is_loopback()) return GN_TRUST_LOOPBACK;
    return GN_TRUST_UNTRUSTED;
}

std::optional<WsLink::ParsedUri> WsLink::parse_uri(
    std::string_view uri) {
    /// Plain WebSocket only — `wss://` is the same WebSocket protocol
    /// over a TLS-wrapped underlying socket and lands once the
    /// `gn.link.tls` composer plugin ships. The composer model
    /// keeps WS framing in this plugin and TLS encryption in its
    /// own; nothing changes about the framing on the wire.
    constexpr std::string_view kWs = "ws://";
    if (!uri.starts_with(kWs)) return std::nullopt;

    /// `gn::parse_uri` handles bracket-IPv6, port parsing, and
    /// scheme stripping but does not split authority from a path
    /// suffix. Strip the WebSocket resource path here so the
    /// shared parser sees a clean `ws://authority` slice and the
    /// path travels separately into the upgrade handshake.
    auto rest = uri.substr(kWs.size());
    std::string path;
    if (const auto slash = rest.find('/'); slash != std::string_view::npos) {
        path.assign(rest.substr(slash));
        rest = rest.substr(0, slash);
    }
    std::string canonical;
    canonical.reserve(kWs.size() + rest.size());
    canonical.append(kWs);
    canonical.append(rest);

    const auto parts = ::gn::parse_uri(canonical);
    if (!parts || parts->scheme != "ws" || parts->is_path_style()) {
        return std::nullopt;
    }
    if (parts->host.empty()) return std::nullopt;
    ParsedUri pr;
    pr.host = parts->host;
    /// A `ws://host:0` URI on listen means "ephemeral port"; the
    /// connect-side caller asserts `port != 0` separately.
    pr.port = parts->port;
    pr.path = path.empty() ? std::string{"/"} : std::move(path);
    return pr;
}

std::string WsLink::endpoint_to_uri(
    const asio::ip::tcp::endpoint& ep, std::string_view path) {
    std::ostringstream s;
    s << "ws://";
    if (ep.address().is_v6()) {
        s << '[' << ep.address().to_string() << ']';
    } else {
        s << ep.address().to_string();
    }
    s << ':' << ep.port() << path;
    return s.str();
}

gn_result_t WsLink::listen(std::string_view uri) {
    auto parsed = parse_uri(uri);
    if (!parsed) return GN_ERR_INVALID_ENVELOPE;

    asio::ip::tcp::endpoint ep;
    try {
        if (parsed->host == "0.0.0.0" || parsed->host == "::") {
            ep = asio::ip::tcp::endpoint(
                parsed->host == "::" ? asio::ip::tcp::v6() : asio::ip::tcp::v4(),
                parsed->port);
        } else {
            ep = asio::ip::tcp::endpoint(
                asio::ip::make_address(parsed->host), parsed->port);
        }
    } catch (...) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    std::error_code ec;
    asio::ip::tcp::acceptor acc(ioc_);
    if (acc.open(ep.protocol(), ec)) {
        if (api_) {
            gn_log_warn(api_,
                "ws: acceptor open failed (uri=%.*s, errno=%d): %s",
                static_cast<int>(uri.size()), uri.data(),
                ec.value(), ec.message().c_str());
        }
        return GN_ERR_NULL_ARG;
    }
    /// IPv6 wildcard `::` — disable `IPV6_V6ONLY` so dual-stack
    /// listens accept v4-mapped clients on Linux. Best-effort:
    /// pre-Linux-3.x kernels lack the option and the connection
    /// stays v4-only. Specific v6 literals stay v6-only by default.
    if (ep.address().is_v6() && ep.address().is_unspecified()) {
        std::error_code v6_ec;
        // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
        acc.set_option(asio::ip::v6_only(false), v6_ec);
        if (v6_ec && api_) {
            gn_log_debug(api_, "ws: v6_only(false) failed: %s",
                         v6_ec.message().c_str());
        }
    }
    if (acc.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec)) {
        if (api_) {
            gn_log_warn(api_,
                "ws: reuse_address failed (uri=%.*s, errno=%d): %s",
                static_cast<int>(uri.size()), uri.data(),
                ec.value(), ec.message().c_str());
        }
        return GN_ERR_LIMIT_REACHED;
    }
    if (acc.bind(ep, ec)) {
        if (api_) {
            gn_log_warn(api_,
                "ws: bind failed (uri=%.*s, errno=%d): %s",
                static_cast<int>(uri.size()), uri.data(),
                ec.value(), ec.message().c_str());
        }
        return GN_ERR_LIMIT_REACHED;
    }
    if (acc.listen(asio::socket_base::max_listen_connections, ec)) {
        if (api_) {
            gn_log_warn(api_,
                "ws: listen failed (uri=%.*s, errno=%d): %s",
                static_cast<int>(uri.size()), uri.data(),
                ec.value(), ec.message().c_str());
        }
        return GN_ERR_LIMIT_REACHED;
    }
    listen_port_.store(acc.local_endpoint().port(),
                        std::memory_order_release);
    acceptor_.emplace(std::move(acc));
    start_accept();
    return GN_OK;
}

void WsLink::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    /// Build the Session up front so its socket is constructed
    /// against the io_context before async_accept binds to it.
    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this(),
        Session::Mode::Server);
    if (!acceptor_.has_value()) return;
    auto& sock = session->socket();
    /// Async accept holds a weak observer of the transport
    /// (`plugin-lifetime.md` §4) so a queued completion never
    /// extends the transport past its kernel-side lifetime.
    acceptor_->async_accept(sock,
        [weak = weak_from_this(),
         session = std::move(session)](const std::error_code& ec) mutable {
            auto self = weak.lock();
            if (!self) return;
            if (self->shutdown_.load(std::memory_order_acquire)) return;
            if (ec) { self->start_accept(); return; }
            /// Disable Nagle: WS pings, pongs, and small framed
            /// app messages must not wait on the kernel's
            /// coalescing timer. Best-effort.
            std::error_code nodelay_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            session->socket().set_option(
                asio::ip::tcp::no_delay{true}, nodelay_ec);
            if (nodelay_ec && self->api_) {
                gn_log_debug(self->api_, "ws: TCP_NODELAY refused: %s",
                             nodelay_ec.message().c_str());
            }
            session->start_server_handshake();
            self->start_accept();
        });
}

gn_result_t WsLink::connect(std::string_view uri) {
    /// Hostname → IP literal up-front per `dns.md` §1; the helper
    /// short-circuits IP-literal hosts. The HTTP `Host:` header sent
    /// during the upgrade carries the literal `host:port`, matching
    /// the registry key the kernel will use.
    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    auto parsed = parse_uri(*resolved);
    if (!parsed) return GN_ERR_INVALID_ENVELOPE;

    asio::ip::tcp::endpoint ep;
    try {
        ep = asio::ip::tcp::endpoint(
            asio::ip::make_address(parsed->host), parsed->port);
    } catch (const std::exception&) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// `host_authority()` re-brackets IPv6 literals per RFC 7230
    /// §5.4 — strict servers (nginx, Caddy) reject `Host: ::1:9000`.
    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this(),
        Session::Mode::Client);
    auto& sock = session->socket();
    sock.async_connect(ep,
        [weak = weak_from_this(),
         session,
         host = parsed->host_authority(),
         path = parsed->path](const std::error_code& cec) {
            if (cec) {
                /// Connect failed before any `notify_connect` could
                /// publish — kernel has no record to release, so
                /// the diagnostic is operator-facing only. Without
                /// the warn, the outbound URI sat in the WS log
                /// silently; per `link.md` §9 a connect failure is
                /// not a session release event but still must be
                /// observable.
                if (auto t = weak.lock(); t && t->api_) {
                    gn_log_warn(t->api_,
                        "ws: connect to %s failed: %s",
                        host.c_str(), cec.message().c_str());
                }
                return;
            }
            /// Disable Nagle on the outbound side, mirroring the
            /// accept path. Best-effort.
            std::error_code nodelay_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            session->socket().set_option(
                asio::ip::tcp::no_delay{true}, nodelay_ec);
            (void)nodelay_ec;
            session->start_client_handshake(host, path);
        });
    return GN_OK;
}

gn_result_t WsLink::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes) {
    if (bytes.size() > kMaxFramePayload) return GN_ERR_PAYLOAD_TOO_LARGE;
    auto s = find_session(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    /// Account against the framed wire size — header overhead +
    /// payload — so the cap mirrors what actually sits in
    /// `write_queue_`.
    const auto framed = bytes.size() + 14U;
    if (pending_queue_bytes_hard_ != 0 &&
        s->bytes_buffered() + framed > pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "ws.send: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                s->bytes_buffered(),
                framed,
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    s->enqueue_send(bytes);
    return GN_OK;
}

gn_result_t WsLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    /// Coalesce into one logical message — single-writer invariant.
    std::size_t total = 0;
    for (const auto& f : frames) total += f.size();
    if (total > kMaxFramePayload) return GN_ERR_PAYLOAD_TOO_LARGE;
    std::vector<std::uint8_t> coalesced;
    coalesced.reserve(total);
    for (const auto& f : frames) {
        coalesced.insert(coalesced.end(), f.begin(), f.end());
    }
    auto s = find_session(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    const auto framed = total + 14U;
    if (pending_queue_bytes_hard_ != 0 &&
        s->bytes_buffered() + framed > pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "ws.send_batch: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                s->bytes_buffered(),
                framed,
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    s->enqueue_send(std::span<const std::uint8_t>(coalesced));
    return GN_OK;
}

gn_result_t WsLink::disconnect(gn_conn_id_t conn) {
    auto s = find_session(conn);
    if (!s) return GN_OK;
    s->enqueue_close();
    return GN_OK;
}

void WsLink::shutdown() {
    /// Side-effect block runs only on the first call. The join
    /// below runs on every call so a second `shutdown()` from a
    /// non-worker thread can finish the join that the first
    /// (worker-thread) call had to skip.
    if (!shutdown_.exchange(true, std::memory_order_acq_rel)) {
        if (acceptor_) {
            std::error_code ec;
            if (acceptor_->close(ec)) {}
        }

        /// Snapshot conn ids under the lock, post the per-session
        /// close onto each session's strand, then notify the kernel
        /// side SYNCHRONOUSLY for each session before stopping the
        /// io_context. `ioc_.stop()` would otherwise drop pending
        /// strand-bound continuations — including the read-
        /// completion path that normally fires `notify_disconnect`.
        /// Without sync notification, kernel-side
        /// `ConnectionRegistry` keeps live records past ws shutdown,
        /// which in turn keeps the security plugin's lifetime
        /// anchor alive past the PluginManager drain budget. Per
        /// `link.md` §9 the shutdown must release every kernel-
        /// observable session before the io_context tear-down.
        std::vector<gn_conn_id_t> live_ids;
        {
            std::lock_guard lk(sessions_mu_);
            live_ids.reserve(sessions_.size());
            for (auto& [id, s] : sessions_) {
                live_ids.push_back(id);
                s->enqueue_close();
            }
            sessions_.clear();
        }

        if (api_ && api_->notify_disconnect) {
            for (const auto id : live_ids) {
                (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
            }
        }

        work_.reset();
        ioc_.stop();
    }

    /// Join only when we're not the worker. Joining oneself
    /// returns EDEADLK; the dtor catches a still-joinable thread
    /// after `shutdown()` returns and surfaces it as an ownership-
    /// cycle diagnostic.
    if (worker_.joinable() &&
        std::this_thread::get_id() != worker_.get_id()) {
        worker_.join();
    }
}

void WsLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_.emplace(id, std::move(s));
}

void WsLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<WsLink::Session>
WsLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return it == sessions_.end() ? nullptr : it->second;
}

} // namespace gn::link::ws
