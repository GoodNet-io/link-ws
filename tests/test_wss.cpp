// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/tests/test_wss.cpp
/// @brief  End-to-end `wss://` round-trip — exercises the two-layer
///         composer chain: WS framing over TLS over TCP, all driven by
///         `LinkCarrier`. This is the canonical validation that the
///         composer pattern stacks correctly: WS asks for
///         `gn.link.tls`, TLS in turn asks for `gn.link.tcp`, and a
///         single in-process harness routes both queries to live link
///         instances.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <tcp.hpp>
#include <tls.hpp>
#include <wire.hpp>
#include <ws.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include "../../tls/tests/support/test_self_signed_cert.hpp"

namespace ws_wire = gn::link::ws::wire;

namespace {

/// Bridge a TcpLink into the `gn_link_api_t` shape — same pattern as
/// `test_ws.cpp`. Lives next to the TLS carrier so a `wss://` test
/// can stand both up in one host_api at once.
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
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->send(
            c, std::span<const std::uint8_t>(b, n));
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
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<TcpCarrierBridge*>(ctx)->tcp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<TcpCarrierBridge*>(ctx)
            ->tcp->composer_listen_port(out);
    }
};

/// Bridge a TlsLink into the `gn_link_api_t` shape. The TLS plugin
/// internally queries `gn.link.tcp` through the same host_api, so
/// this bridge has to share the harness's TCP carrier (the harness's
/// `query_extension_checked` returns both).
struct TlsCarrierBridge {
    std::shared_ptr<gn::link::tls::TlsLink> tls;
    gn_link_api_t vtable{};

    TlsCarrierBridge() : tls(std::make_shared<gn::link::tls::TlsLink>()) {
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
        if (out) *out = gn::link::tls::TlsLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<TlsCarrierBridge*>(ctx)->tls->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_send_batch(void* ctx, gn_conn_id_t c,
                                     const gn_byte_span_t* batch,
                                     std::size_t count) {
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return static_cast<TlsCarrierBridge*>(ctx)->tls->send_batch(c,
            std::span<const std::span<const std::uint8_t>>(frames));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<TlsCarrierBridge*>(ctx)->tls->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<TlsCarrierBridge*>(ctx)
            ->tls->composer_listen_port(out);
    }
};

/// WSS-aware test harness — exposes BOTH `gn.link.tcp` and
/// `gn.link.tls` extensions through one `query_extension_checked`
/// thunk. The TLS bridge's TlsLink also receives a host_api binding
/// (with this same query thunk) so its internal `ensure_carrier("tcp")`
/// can find the TCP carrier registered alongside it.
struct WssHarness {
    std::mutex                              mu;
    std::vector<gn_conn_id_t>               connects;
    std::vector<gn_handshake_role_t>        roles;
    std::vector<std::vector<std::uint8_t>>  inbound;
    std::vector<gn_conn_id_t>               disconnects;
    std::atomic<gn_conn_id_t>               next_id{1};

    TcpCarrierBridge tcp_bridge;
    TlsCarrierBridge tls_bridge;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t*,
                                         const char*,
                                         gn_trust_class_t,
                                         gn_handshake_role_t role,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<WssHarness*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        std::lock_guard lk(h->mu);
        h->connects.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void* host_ctx, gn_conn_id_t,
                                         const std::uint8_t* bytes,
                                         std::size_t size) {
        auto* h = static_cast<WssHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t conn,
                                            gn_result_t) {
        auto* h = static_cast<WssHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->disconnects.push_back(conn);
        return GN_OK;
    }
    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }
    static gn_result_t s_query_extension(void* host_ctx, const char* name,
                                           std::uint32_t version,
                                           const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<WssHarness*>(host_ctx);
        const std::string_view n{name};
        if (n == "gn.link.tcp") {
            *out = &h->tcp_bridge.vtable;
            return GN_OK;
        }
        if (n == "gn.link.tls") {
            *out = &h->tls_bridge.vtable;
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
              std::chrono::milliseconds timeout = std::chrono::seconds{15}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

}  // namespace

TEST(WssE2E, HandshakeAndPayloadRoundTrip) {
    WssHarness harness;
    auto api = harness.make_api();

    /// Generate a self-signed cert / key the TLS carrier serves.
    /// Client trust verification is disabled — TLS underneath WS is
    /// for wire encryption, not peer auth (the kernel's Noise layer
    /// above does authentication when needed).
    std::string cert_pem;
    std::string key_pem;
    ASSERT_TRUE(gn::tests::support::generate_self_signed(cert_pem, key_pem));
    harness.tls_bridge.tls->set_server_credentials(cert_pem, key_pem);
    /// `set_host_api` resets verify_peer to the default-secure baseline
    /// (true) before re-applying the `links.tls.verify_peer` config
    /// opt-out — the harness has no config_get, so we toggle the
    /// opt-out manually AFTER the host_api binding settles.
    harness.tls_bridge.tls->set_host_api(&api);
    harness.tls_bridge.tls->set_verify_peer(false);

    auto server = std::make_shared<gn::link::ws::WsLink>();
    auto client = std::make_shared<gn::link::ws::WsLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("wss://127.0.0.1:0/"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "wss://127.0.0.1:" + std::to_string(port) + "/";
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    })) << "wss: both notify_connect must fire";

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

    /// Payload roundtrip — bytes traverse WS framing → TLS encryption →
    /// TCP carrier → TLS decryption → WS unframing → notify_inbound.
    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44, 0x55};
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
    auto rc1 = client->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    auto rc2 = server->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    EXPECT_TRUE(rc1 == GN_OK || rc2 == GN_OK);

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return !harness.inbound.empty();
    })) << "wss: payload did not surface through the carrier stack";
    {
        std::lock_guard lk(harness.mu);
        ASSERT_FALSE(harness.inbound.empty());
        EXPECT_EQ(harness.inbound.front(), payload);
    }

    client->shutdown();
    server->shutdown();
    /// TlsLink is shared between server and client WsLinks; its
    /// shutdown drains both directions through the same carrier.
    harness.tls_bridge.tls->shutdown();
}
