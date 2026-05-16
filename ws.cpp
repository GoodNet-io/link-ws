// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/ws.cpp
/// @brief  Composer-mode WebSocket transport — RFC 6455 framing
///         layered on a `gn.link.<scheme>` L1 carrier (today `tcp`,
///         later `tls` for `wss://`).

#include "ws.hpp"

#include "wire.hpp"
#include "ws_http_parse.hpp"
#include "ws_session.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/io_context.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace gn::link::ws {

/// `Session`, helper trio (`make_sec_websocket_key`, `make_mask_seed`,
/// `iequals`), and HTTP/1.1 request / response parsers live in
/// `ws_session.hpp` + `ws_http_parse.hpp`. The header-only forms
/// stay inline so this TU pays nothing for the move beyond two
/// extra `#include`s.

// ── WsLink ───────────────────────────────────────────────────────────────

WsLink::WsLink() = default;

WsLink::~WsLink() {
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "ws: shutdown threw: %s", e.what());
        }
    } catch (...) {  // NOLINT(bugprone-empty-catch)
        // dtor stays noexcept; non-std exceptions silently swallowed.
    }
}

void WsLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    if (api_ != nullptr && api_->limits != nullptr) {
        if (const auto* L = api_->limits(api_->host_ctx); L != nullptr) {
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
    auto s = find_session_by_ws(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    return s->send_raw(bytes);
}

std::uint16_t WsLink::listen_port() const noexcept {
    if (!carrier_) return 0;
    return carrier_->listen_port();
}

std::size_t WsLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return by_ws_.size();
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

gn_trust_class_t WsLink::resolve_trust_from_uri(
    std::string_view peer_uri) noexcept {
    /// The carrier's peer URI is the canonical L1 form,
    /// `tcp://host:port` / `tls://host:port`. Strip the scheme prefix
    /// and check for loopback literals; everything else is
    /// `Untrusted` per `link.md` §3 — trust upgrades to `Peer` after
    /// Noise completes above us.
    const auto colon = peer_uri.find("://");
    const auto host_start = colon == std::string_view::npos
        ? std::size_t{0} : colon + 3;
    std::string_view rest = peer_uri.substr(host_start);
    /// Trim trailing `:port` portion to leave a bare host literal.
    /// IPv6 literals come wrapped in `[...]`; loopback we accept
    /// is the unwrapped form `::1`.
    if (!rest.empty() && rest.front() == '[') {
        const auto close = rest.find(']');
        if (close == std::string_view::npos) return GN_TRUST_UNTRUSTED;
        rest = rest.substr(1, close - 1);
    } else {
        const auto last_colon = rest.rfind(':');
        if (last_colon != std::string_view::npos) {
            rest = rest.substr(0, last_colon);
        }
    }
    if (rest == "127.0.0.1" || rest == "::1") return GN_TRUST_LOOPBACK;
    if (rest.starts_with("127.")) return GN_TRUST_LOOPBACK;
    /// IPv4-mapped IPv6 loopback — a v4 client connecting through a
    /// dual-stack v6 listener arrives as `::ffff:127.x.x.x`. Without
    /// this branch the trust resolver classifies the connection as
    /// `Untrusted` even though the underlying address is loopback,
    /// which makes test fixtures that drive a v6 acceptor flake on
    /// the trust-class assertion.
    if (rest.starts_with("::ffff:127.")) return GN_TRUST_LOOPBACK;
    return GN_TRUST_UNTRUSTED;
}

std::string WsLink::rewrite_peer_uri(
    std::string_view carrier_peer_uri, bool secure) {
    /// `tcp://host:port` → `ws://host:port`; `tls://host:port` →
    /// `wss://host:port`. The canonical kernel-facing scheme stays
    /// consistent with the WS public URI form even though the L1
    /// underneath is a different scheme.
    const auto colon = carrier_peer_uri.find("://");
    if (colon == std::string_view::npos) {
        return std::string{carrier_peer_uri};
    }
    std::string out;
    out.reserve(carrier_peer_uri.size());
    out += secure ? "wss" : "ws";
    out.append(carrier_peer_uri.substr(colon));
    return out;
}

std::optional<WsLink::ParsedUri> WsLink::parse_uri(
    std::string_view uri) {
    /// Accept both `ws://` (plain) and `wss://` (TLS-tunnelled).
    /// `gn::parse_uri` handles bracket-IPv6, port parsing, and
    /// scheme stripping but does not split authority from a path
    /// suffix. Strip the WebSocket resource path here so the shared
    /// parser sees a clean `<scheme>://authority` slice and the path
    /// travels separately into the upgrade handshake.
    constexpr std::string_view kWs  = "ws://";
    constexpr std::string_view kWss = "wss://";
    bool secure = false;
    std::string_view scheme_prefix;
    if (uri.starts_with(kWss)) {
        secure = true;
        scheme_prefix = kWss;
    } else if (uri.starts_with(kWs)) {
        scheme_prefix = kWs;
    } else {
        return std::nullopt;
    }

    auto rest = uri.substr(scheme_prefix.size());
    std::string path;
    if (const auto slash = rest.find('/'); slash != std::string_view::npos) {
        path.assign(rest.substr(slash));
        rest = rest.substr(0, slash);
    }
    std::string canonical;
    canonical.reserve(scheme_prefix.size() + rest.size());
    canonical.append(scheme_prefix);
    canonical.append(rest);

    const auto parts = ::gn::parse_uri(canonical);
    if (!parts || parts->is_path_style()) return std::nullopt;
    if (!secure && parts->scheme != "ws")  return std::nullopt;
    if (secure  && parts->scheme != "wss") return std::nullopt;
    if (parts->host.empty()) return std::nullopt;

    /// `ParsedUri` inherits the canonical authority/scheme fields
    /// from `gn::UriParts`; copy the parent slice through and add
    /// the WS-specific `http_path` + `secure` on top. A `ws://host:0`
    /// URI on listen means "ephemeral port"; the connect-side caller
    /// asserts `port != 0` separately.
    ParsedUri pr;
    static_cast<::gn::UriParts&>(pr) = *parts;
    pr.http_path = path.empty() ? std::string{"/"} : std::move(path);
    pr.secure    = secure;
    return pr;
}

gn_result_t WsLink::ensure_carrier(bool secure) {
    if (carrier_) {
        if (carrier_secure_ != secure) {
            gn_log_warn(api_, "ws: ensure_carrier scheme conflict — "
                              "carrier already bound to %s but "
                              "request wants %s",
                        carrier_secure_ ? "tls" : "tcp",
                        secure ? "tls" : "tcp");
            return GN_ERR_INVALID_STATE;
        }
        return GN_OK;
    }
    if (!api_) return GN_ERR_INVALID_STATE;
    const std::string_view scheme = secure ? "tls" : "tcp";
    auto opt = gn::sdk::LinkCarrier::query(api_, scheme);
    if (!opt) {
        gn_log_warn(api_, "ws: ensure_carrier query gn.link.%.*s "
                          "extension missing — load the carrier plugin "
                          "before ws://wss://",
                    static_cast<int>(scheme.size()), scheme.data());
        return GN_ERR_NOT_FOUND;
    }
    carrier_.emplace(std::move(*opt));
    carrier_secure_ = secure;
    return GN_OK;
}

gn_result_t WsLink::listen(std::string_view uri) {
    auto parsed = parse_uri(uri);
    if (!parsed) {
        gn_log_warn(api_, "ws: listen reject malformed uri %.*s "
                          "(expected ws:// or wss://)",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (const auto rc = ensure_carrier(parsed->secure); rc != GN_OK) {
        return rc;
    }
    auto self_weak = weak_from_this();
    const auto rc = carrier_->on_accept(
        [self_weak](gn_conn_id_t l1, std::string_view peer_uri) {
            if (auto t = self_weak.lock()) {
                t->compose_server_session(l1, peer_uri);
            }
        });
    if (rc != GN_OK) return rc;
    std::string l1_uri;
    l1_uri.reserve(parsed->host.size() + 16);
    l1_uri += parsed->secure ? "tls://" : "tcp://";
    l1_uri += parsed->host;
    l1_uri += ':';
    l1_uri += std::to_string(parsed->port);
    return carrier_->listen(l1_uri);
}

void WsLink::compose_server_session(gn_conn_id_t l1,
                                     std::string_view peer_uri) {
    auto self = shared_from_this();
    auto session = std::make_shared<Session>(
        weak_from_this(), l1, Session::Mode::Server);
    session->peer_uri_ =
        rewrite_peer_uri(peer_uri, carrier_secure_);
    session->trust_    = resolve_trust_from_uri(peer_uri);
    {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.load(std::memory_order_acquire)) return;
        by_l1_[l1] = session;
    }
    if (!carrier_) return;
    std::weak_ptr<Session> sess_weak = session;
    (void)carrier_->on_data(l1,
        [sess_weak](gn_conn_id_t /*conn*/,
                    std::span<const std::uint8_t> bytes) {
            if (auto s = sess_weak.lock()) {
                s->feed_inbound(bytes);
            }
        });
}

gn_result_t WsLink::connect(std::string_view uri) {
    /// One-shot io_context for the synchronous DNS resolve below.
    /// WS no longer owns an io_context for I/O — the carrier does —
    /// but the resolver helper still demands one for the asio
    /// `resolver` instance. Stack-scoped, destroyed before we hand
    /// off to the carrier.
    asio::io_context resolver_ioc;
    auto resolved = ::gn::sdk::resolve_uri_host(resolver_ioc, uri);
    if (!resolved) {
        gn_log_warn(api_, "ws: connect DNS resolve failed for %.*s",
                    static_cast<int>(uri.size()), uri.data());
        return GN_ERR_INVALID_ENVELOPE;
    }

    auto parsed = parse_uri(*resolved);
    if (!parsed) {
        gn_log_warn(api_, "ws: connect reject malformed resolved uri "
                          "%.*s (expected ws:// or wss://)",
                    static_cast<int>(resolved->size()), resolved->data());
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (const auto rc = ensure_carrier(parsed->secure); rc != GN_OK) {
        return rc;
    }

    std::string l1_uri;
    l1_uri.reserve(parsed->host.size() + 16);
    l1_uri += parsed->secure ? "tls://" : "tcp://";
    l1_uri += parsed->host;
    l1_uri += ':';
    l1_uri += std::to_string(parsed->port);

    gn_conn_id_t l1 = GN_INVALID_ID;
    if (!carrier_) return GN_ERR_INVALID_STATE;
    const auto rc = carrier_->connect(l1_uri, &l1);
    if (rc != GN_OK) {
        if (api_) {
            gn_log_warn(api_,
                "ws: carrier connect failed (uri=%.*s, rc=%d)",
                static_cast<int>(uri.size()), uri.data(),
                static_cast<int>(rc));
        }
        return rc;
    }
    auto session = std::make_shared<Session>(
        weak_from_this(), l1, Session::Mode::Client);
    /// For the client side the canonical scheme'd URI is the public
    /// one the caller asked for, so the kernel record stays
    /// consistent across both ends.
    session->peer_uri_ = std::string{*resolved};
    session->trust_ = GN_TRUST_UNTRUSTED;
    {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.load(std::memory_order_acquire)) {
            (void)carrier_->disconnect(l1);
            return GN_ERR_INVALID_STATE;
        }
        by_l1_[l1] = session;
    }
    std::weak_ptr<Session> sess_weak = session;
    (void)carrier_->on_data(l1,
        [sess_weak](gn_conn_id_t /*conn*/,
                    std::span<const std::uint8_t> bytes) {
            if (auto s = sess_weak.lock()) {
                s->feed_inbound(bytes);
            }
        });
    session->start_client_handshake(parsed->host_authority(),
                                      parsed->http_path);
    return GN_OK;
}

gn_result_t WsLink::send(gn_conn_id_t conn,
                          std::span<const std::uint8_t> bytes) {
    if (bytes.size() > kMaxFramePayload) return GN_ERR_PAYLOAD_TOO_LARGE;
    auto s = find_session_by_ws(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    return s->enqueue_send(bytes);
}

gn_result_t WsLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    std::size_t total = 0;
    for (const auto& f : frames) total += f.size();
    if (total > kMaxFramePayload) return GN_ERR_PAYLOAD_TOO_LARGE;
    std::vector<std::uint8_t> coalesced;
    coalesced.reserve(total);
    for (const auto& f : frames) {
        coalesced.insert(coalesced.end(), f.begin(), f.end());
    }
    auto s = find_session_by_ws(conn);
    if (!s) return GN_ERR_NOT_FOUND;
    return s->enqueue_send(
        std::span<const std::uint8_t>(coalesced));
}

gn_result_t WsLink::disconnect(gn_conn_id_t conn) {
    auto s = find_session_by_ws(conn);
    if (!s) return GN_OK;
    s->enqueue_close();
    return GN_OK;
}

void WsLink::shutdown() {
    /// `shutdown_.exchange(true)` runs INSIDE the lock so worker
    /// callbacks (carrier data-bus invocations) racing with shutdown
    /// either (a) win the lock, see `shutdown_=false`, claim their id,
    /// and emit on the worker thread, or (b) lose, see
    /// `shutdown_=true`, and bail — the drain below then carries the
    /// kernel-observable release on the caller thread either way. The
    /// kernel resolves the resulting double-emit through
    /// `GN_ERR_NOT_FOUND` (`host_api_builder.cpp` thunk_notify_disconnect).
    bool first_call = false;
    std::vector<gn_conn_id_t> ids_to_emit;
    std::vector<std::shared_ptr<Session>> sessions_to_close;
    {
        std::lock_guard lk(sessions_mu_);
        if (!shutdown_.exchange(true, std::memory_order_acq_rel)) {
            first_call = true;
            ids_to_emit = std::move(published_ids_);
            published_ids_.clear();
            sessions_to_close.reserve(by_l1_.size());
            for (auto& [l1, s] : by_l1_) {
                sessions_to_close.push_back(s);
            }
            by_l1_.clear();
            by_ws_.clear();
        }
    }
    if (!first_call) return;

    for (auto& s : sessions_to_close) {
        s->enqueue_close();
    }
    sessions_to_close.clear();

    /// Notify the kernel side SYNCHRONOUSLY for each published session
    /// before dropping the carrier. The carrier dtor unsubscribes
    /// data + accept callbacks so no further worker-thread events can
    /// fire; without sync notification, kernel-side
    /// `ConnectionRegistry` keeps live records past WS shutdown.
    if (api_ && api_->notify_disconnect) {
        for (const auto id : ids_to_emit) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    /// Release the carrier handle — RAII unsubscribes every data /
    /// accept callback the WsLink installed.
    carrier_.reset();
}

void WsLink::register_session(gn_conn_id_t ws_id,
                               std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    by_ws_[ws_id] = std::move(s);
    published_ids_.push_back(ws_id);
}

bool WsLink::claim_disconnect(gn_conn_id_t ws_id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    return by_ws_.erase(ws_id) > 0;
}

void WsLink::drop_l1_mapping(gn_conn_id_t l1) {
    std::lock_guard lk(sessions_mu_);
    by_l1_.erase(l1);
}

std::shared_ptr<WsLink::Session>
WsLink::find_session_by_ws(gn_conn_id_t ws_id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = by_ws_.find(ws_id);
    return it == by_ws_.end() ? nullptr : it->second;
}

std::shared_ptr<WsLink::Session>
WsLink::find_session_by_l1(gn_conn_id_t l1) const {
    std::lock_guard lk(sessions_mu_);
    auto it = by_l1_.find(l1);
    return it == by_l1_.end() ? nullptr : it->second;
}

} // namespace gn::link::ws
