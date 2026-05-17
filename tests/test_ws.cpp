/// @file   plugins/links/ws/tests/test_ws.cpp
/// @brief  RFC 6455 framing + URI parsing + loopback round-trip
///         coverage for the `ws` transport plugin, now layered on
///         `gn.link.tcp` via `LinkCarrier`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <tcp.hpp>
#include <wire.hpp>
#include <ws.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace ws_wire = gn::link::ws::wire;

namespace {

/// Bridge a `gn::link::tcp::TcpLink` instance to the `gn_link_api_t`
/// extension surface so a WsLink in the same test process can query
/// it through `LinkCarrier`. The bridge holds a single TcpLink that
/// both the WS server and WS client share — composer_acceptor_ runs
/// on one side (server.listen), composer_connect runs on the other.
/// Two different composer L1 conns (server-inbound, client-outbound)
/// exist on the shared TcpLink without colliding.
struct TcpCarrierBridge {
    std::shared_ptr<gn::link::tcp::TcpLink> tcp;
    gn_link_api_t vtable{};

    TcpCarrierBridge() : tcp(std::make_shared<gn::link::tcp::TcpLink>()) {
        vtable.api_size             = sizeof(vtable);
        vtable.get_stats            = &s_get_stats;
        vtable.get_capabilities     = &s_get_caps;
        vtable.send                 = &s_send;
        vtable.send_batch           = &s_send_batch;
        vtable.close                = &s_close;
        vtable.listen               = &s_listen;
        vtable.connect              = &s_connect;
        vtable.subscribe_data       = &s_subscribe_data;
        vtable.unsubscribe_data     = &s_unsubscribe_data;
        vtable.subscribe_accept     = &s_subscribe_accept;
        vtable.unsubscribe_accept   = &s_unsubscribe_accept;
        vtable.composer_listen_port = &s_listen_port;
        vtable.ctx                  = this;
    }

    static gn_result_t s_get_stats(void*, gn_link_stats_t* out) {
        if (out) std::memset(out, 0, sizeof(*out));
        return GN_OK;
    }
    static gn_result_t s_get_caps(void*, gn_link_caps_t* out) {
        if (out) *out = gn::link::tcp::TcpLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->send(c,
            std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_send_batch(void* ctx, gn_conn_id_t c,
                                     const gn_byte_span_t* batch,
                                     std::size_t count) {
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->send_batch(c,
            std::span<const std::span<const std::uint8_t>>(frames));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int /*hard*/) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->composer_connect(
            uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp
            ->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp
            ->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                           gn_link_accept_cb_t cb,
                                           void* ud,
                                           gn_subscription_id_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp
            ->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp
            ->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp
            ->composer_listen_port(out);
    }
};

/// Tiny test harness that swallows transport callbacks so the
/// loopback round-trip can be observed from outside the worker
/// threads. Provides a `query_extension_checked` so WS can find the
/// embedded TcpCarrierBridge as `gn.link.tcp`.
struct WsHarness {
    std::mutex                                  mu;
    std::vector<gn_conn_id_t>                   connects;
    std::vector<gn_handshake_role_t>            roles;
    std::vector<std::vector<std::uint8_t>>      inbound;
    std::vector<gn_conn_id_t>                   disconnects;
    std::atomic<gn_conn_id_t>                   next_id{1};

    TcpCarrierBridge tcp_bridge;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t role,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        std::lock_guard lk(h->mu);
        h->connects.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void* host_ctx, gn_conn_id_t /*conn*/,
                                         const std::uint8_t* bytes,
                                         std::size_t size) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t conn,
                                            gn_result_t /*reason*/) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->disconnects.push_back(conn);
        return GN_OK;
    }
    static gn_result_t s_kick(void* /*host_ctx*/, gn_conn_id_t /*conn*/) {
        return GN_OK;
    }
    static gn_result_t s_query_extension(void* host_ctx, const char* name,
                                          std::uint32_t version,
                                          const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        auto* h = static_cast<WsHarness*>(host_ctx);
        if (std::string_view{name} == "gn.link.tcp" &&
            version == GN_EXT_LINK_VERSION) {
            *out = &h->tcp_bridge.vtable;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size                 = sizeof(host_api_t);
        api.host_ctx                 = this;
        api.notify_connect           = &s_notify_connect;
        api.notify_inbound_bytes     = &s_notify_inbound;
        api.notify_disconnect        = &s_notify_disconnect;
        api.kick_handshake           = &s_kick;
        api.query_extension_checked  = &s_query_extension;
        return api;
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{5}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

} // namespace

// ── frame layout ─────────────────────────────────────────────────────────

TEST(WsWire, SmallPayloadFrame) {
    const std::uint8_t payload[] = {0x01, 0x02, 0x03};
    auto frame = ws_wire::build_binary_frame(
        std::span<const std::uint8_t>(payload), /*mask=*/false, 0);

    ASSERT_GE(frame.size(), 2u);
    EXPECT_EQ(frame[0], 0x82u);  // FIN | binary
    EXPECT_EQ(frame[1], 0x03u);  // unmasked, len=3

    auto h = ws_wire::parse_frame_header(
        std::span<const std::uint8_t>(frame));
    ASSERT_TRUE(h.has_value());
    if (!h.has_value()) return;
    const auto hv = *h;
    EXPECT_TRUE(hv.fin);
    EXPECT_EQ(hv.opcode, 0x2u);
    EXPECT_FALSE(hv.masked);
    EXPECT_EQ(hv.payload_len, 3u);
    EXPECT_EQ(hv.header_size, 2u);
}

TEST(WsWire, MaskedPayloadRoundTrip) {
    /// 200-byte payload exercises the 16-bit length field and
    /// the masking path used on every client-to-server frame.
    std::vector<std::uint8_t> payload(200);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i);
    }
    auto frame = ws_wire::build_binary_frame(
        std::span<const std::uint8_t>(payload), /*mask=*/true,
        /*mask_seed=*/0xDEADBEEFu);

    auto h = ws_wire::parse_frame_header(
        std::span<const std::uint8_t>(frame));
    ASSERT_TRUE(h.has_value());
    if (!h.has_value()) return;
    const auto hv = *h;
    EXPECT_TRUE(hv.masked);
    EXPECT_EQ(hv.payload_len, 200u);

    std::vector<std::uint8_t> received(
        frame.begin() + static_cast<std::ptrdiff_t>(hv.header_size),
        frame.end());
    ws_wire::apply_mask(
        std::span<std::uint8_t>(received.data(), received.size()),
        hv.mask);
    EXPECT_EQ(received, payload);
}

TEST(WsWire, HandshakeAcceptKnownVector) {
    /// RFC 6455 §1.3 known-answer test: the canonical example from
    /// the spec must produce the canonical accept value.
    EXPECT_EQ(ws_wire::handshake_accept("dGhlIHNhbXBsZSBub25jZQ=="),
              "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// ── URI parsing ──────────────────────────────────────────────────────────

TEST(WsLink_Uri, AcceptsHostPortPath) {
    /// Listen reaches into the L1 carrier through `query_extension_checked`,
    /// so the harness wiring up `gn.link.tcp` is mandatory now — the
    /// previous `WsLink::listen("ws://127.0.0.1:0/foo")` shape did not
    /// even need a host_api binding.
    WsHarness harness;
    auto api = harness.make_api();
    auto t = std::make_shared<gn::link::ws::WsLink>();
    t->set_host_api(&api);
    EXPECT_EQ(t->listen("ws://127.0.0.1:0/foo"), GN_OK);
    EXPECT_GT(t->listen_port(), 0u);
    t->shutdown();
}

TEST(WsLink_Uri, AcceptsWssScheme) {
    /// Pre-refactor `wss://` was rejected because the framing-only WS
    /// plugin had no TLS L1 to layer onto. After the carrier-mode
    /// refactor the URI parser accepts both schemes; whether the
    /// carrier exists at run time is a separate `ensure_carrier`
    /// check that surfaces at listen / connect time.
    auto pr = gn::link::ws::WsLink::parse_uri("wss://127.0.0.1:9000/x");
    ASSERT_TRUE(pr.has_value());
    EXPECT_TRUE(pr->secure);
    EXPECT_EQ(pr->host, "127.0.0.1");
    EXPECT_EQ(pr->port, 9000u);
    EXPECT_EQ(pr->http_path, "/x");
}

TEST(WsLink_Uri, RejectsBareScheme) {
    WsHarness harness;
    auto api = harness.make_api();
    auto t = std::make_shared<gn::link::ws::WsLink>();
    t->set_host_api(&api);
    EXPECT_EQ(t->listen("not-a-uri"), GN_ERR_INVALID_ENVELOPE);
    t->shutdown();
}

// NOLINTBEGIN(bugprone-unchecked-optional-access)
TEST(WsLink_Uri, HostAuthorityBracketsV6) {
    /// RFC 7230 §5.4: an IPv6 literal in the HTTP `Host:` header
    /// must be bracketed. The WS connect path used to emit
    /// `Host: ::1:9000`, which strict servers (nginx, Caddy)
    /// reject. `ParsedUri::host_authority()` is the choke point.
    /// gtest `ASSERT_TRUE(...has_value())` short-circuits the
    /// dereference but tidy can't model the abort, so the same
    /// NOLINT pattern as `tests/unit/util/test_uri.cpp` and
    /// `tests/unit/plugins/security/test_noise.cpp` applies.
    auto v4 = gn::link::ws::WsLink::parse_uri("ws://1.2.3.4:9000/");
    ASSERT_TRUE(v4.has_value());
    EXPECT_EQ(v4->host_authority(), "1.2.3.4:9000");

    auto v6 = gn::link::ws::WsLink::parse_uri("ws://[::1]:9000/");
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v6->host_authority(), "[::1]:9000");

    auto host = gn::link::ws::WsLink::parse_uri("ws://example.com:80/x");
    ASSERT_TRUE(host.has_value());
    EXPECT_EQ(host->host_authority(), "example.com:80");
}
// NOLINTEND(bugprone-unchecked-optional-access)

// ── loopback round-trip ──────────────────────────────────────────────────

TEST(WsLink, LoopbackHandshakeAndPayloadRoundTrip) {
    WsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::ws::WsLink>();
    auto client = std::make_shared<gn::link::ws::WsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("ws://127.0.0.1:0/"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "ws://127.0.0.1:" + std::to_string(port) + "/";
    ASSERT_EQ(client->connect(uri), GN_OK);

    /// Both sides must observe `notify_connect`.
    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    {
        std::lock_guard lk(harness.mu);
        EXPECT_EQ(harness.connects.size(), 2u);
        const bool roles_pair =
            (harness.roles[0] == GN_ROLE_INITIATOR &&
             harness.roles[1] == GN_ROLE_RESPONDER) ||
            (harness.roles[0] == GN_ROLE_RESPONDER &&
             harness.roles[1] == GN_ROLE_INITIATOR);
        EXPECT_TRUE(roles_pair);
    }

    const std::vector<std::uint8_t> payload{0xAA, 0xBB, 0xCC, 0xDD};
    /// The initiator's conn id is whichever was assigned to the
    /// INITIATOR role; the shared harness counter increments per
    /// notify_connect across both transports so we pick the right id.
    gn_conn_id_t initiator_id = 0;
    {
        std::lock_guard lk(harness.mu);
        for (std::size_t i = 0; i < harness.roles.size(); ++i) {
            if (harness.roles[i] == GN_ROLE_INITIATOR) {
                initiator_id = harness.connects[i];
                break;
            }
        }
    }
    ASSERT_NE(initiator_id, 0u);
    /// Both transports share conn ids; either send finds the local
    /// session, the other returns NOT_FOUND.
    auto rc1 = client->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    auto rc2 = server->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    EXPECT_TRUE(rc1 == GN_OK || rc2 == GN_OK)
        << "send must succeed on the side owning the conn id";

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return !harness.inbound.empty();
    }));
    {
        std::lock_guard lk(harness.mu);
        ASSERT_FALSE(harness.inbound.empty());
        EXPECT_EQ(harness.inbound.front(), payload);
    }

    client->shutdown();
    server->shutdown();
}

// ── shutdown discipline — link.en.md §9 sync release ────────────────────────

TEST(WsLink_Shutdown, IsIdempotent) {
    /// Multiple `shutdown()` calls must be safe.
    WsHarness harness;
    auto api = harness.make_api();
    auto t = std::make_shared<gn::link::ws::WsLink>();
    t->set_host_api(&api);
    t->shutdown();
    t->shutdown();
    t->shutdown();
}

TEST(WsLink_Shutdown, SynchronousNotifyDisconnect) {
    /// `link.en.md` §9 — shutdown releases every kernel-observable
    /// session before the carrier tear-down. The append-only
    /// `published_ids_` log carries each session through
    /// `notify_disconnect` on the caller thread regardless of
    /// whether a worker callback already raced ahead.
    WsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::ws::WsLink>();
    auto client = std::make_shared<gn::link::ws::WsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("ws://127.0.0.1:0/"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "ws://127.0.0.1:" + std::to_string(port) + "/";
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    std::size_t connects = 0;
    {
        std::lock_guard lk(harness.mu);
        connects = harness.connects.size();
        EXPECT_EQ(harness.disconnects.size(), 0u);
    }

    client->shutdown();
    server->shutdown();

    std::lock_guard lk(harness.mu);
    EXPECT_EQ(harness.disconnects.size(), connects)
        << "WsLink::shutdown() must fire notify_disconnect "
           "synchronously for every live session before the carrier "
           "is released (link.en.md §9).";
}

// ── backpressure §3.1 — control-reply per-frame size discipline ──────────

TEST(WsLink_PingFlood, ServerDisconnectsOnPongFrameOverflow) {
    /// `backpressure.en.md` §3.1: a peer flooding pings cannot drive
    /// the server to echo arbitrarily large pongs — the server
    /// disconnects when the next pong frame's size would exceed the
    /// per-conn hard cap. With the composer-mode refactor the WS
    /// layer no longer owns a write queue (the carrier does); the
    /// check is now per-frame rather than cumulative, but the abuse
    /// shape it pins is unchanged.
    WsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::link::ws::WsLink>();
    auto client = std::make_shared<gn::link::ws::WsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    /// 200-byte cap so a 250-byte ping payload (server reply is
    /// unmasked → 252 bytes on the wire) does not fit. The server
    /// hits the rejection path on the first reply attempt.
    server->set_pending_queue_bytes_hard_for_test(200);

    ASSERT_EQ(server->listen("ws://127.0.0.1:0/"), GN_OK);
    const auto port = server->listen_port();
    const std::string uri =
        "ws://127.0.0.1:" + std::to_string(port) + "/";
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));

    gn_conn_id_t client_conn = 0;
    {
        std::lock_guard lk(harness.mu);
        for (std::size_t i = 0; i < harness.roles.size(); ++i) {
            if (harness.roles[i] == GN_ROLE_INITIATOR) {
                client_conn = harness.connects[i];
                break;
            }
        }
    }
    ASSERT_NE(client_conn, 0u);

    /// Masked ping with a 250-byte payload — server's pong reply
    /// lands at ~252 bytes, past the 200-byte cap.
    std::vector<std::uint8_t> ping_payload(250, 0xAB);
    auto ping_frame = ws_wire::build_ping_frame(
        std::span<const std::uint8_t>(ping_payload),
        /*mask=*/true, 0x12345678U);

    /// A few pings — only one needs to make the server queue a reply
    /// that exceeds the cap. Send a small batch so the test stays
    /// robust if the very first frame is dropped at TCP receive time
    /// under sanitiser slowdown.
    for (int i = 0; i < 8; ++i) {
        (void)client->send_raw_for_test(client_conn,
            std::span<const std::uint8_t>(ping_frame));
    }

    /// The server publishes `notify_disconnect` when the next pong
    /// would overflow the cap. Both sides observe the disconnect on
    /// the shared harness.
    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return !harness.disconnects.empty();
    }, std::chrono::seconds{30}));

    client->shutdown();
    server->shutdown();
}

// ── transport-extension capabilities ─────────────────────────────────────

TEST(WsLink_Capabilities, AdvertisesStreamReliableOrdered) {
    const auto caps = gn::link::ws::WsLink::capabilities();
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_LINK_CAP_ORDERED);
    EXPECT_FALSE(caps.flags & GN_LINK_CAP_DATAGRAM);
    EXPECT_GT(caps.max_payload, 0u)
        << "WS caps should declare the per-frame payload ceiling";
}
