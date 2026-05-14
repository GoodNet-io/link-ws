// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/tests/test_ws_conformance.cpp
/// @brief  Instantiates the SDK link teardown conformance suite
///         against `gn::link::ws::WsLink`. WS is a composer plugin,
///         so the LinkTraits specialisation installs a TcpLink-backed
///         `gn.link.tcp` carrier on the conformance host before the
///         test body builds the host_api.

#include <sdk/test/conformance/link_teardown.hpp>
#include <tcp.hpp>
#include <ws.hpp>

#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace gn::test::link::conformance {

namespace {

/// Bridge a TcpLink to the `gn_link_api_t` shape. Lives inside the
/// shared ConformanceHost so its lifetime spans every per-test
/// listen / connect / shutdown cycle.
struct WsCarrierBridge {
    std::shared_ptr<gn::link::tcp::TcpLink> tcp;
    gn_link_api_t vtable{};

    WsCarrierBridge()
        : tcp(std::make_shared<gn::link::tcp::TcpLink>()) {
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
        return static_cast<WsCarrierBridge*>(ctx)->tcp->send(
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
        return static_cast<WsCarrierBridge*>(ctx)->tcp->send_batch(c,
            std::span<const std::span<const std::uint8_t>>(frames));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<WsCarrierBridge*>(ctx)->tcp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_connect(uri, out);
    }
    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb, void* ud) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_subscribe_data(c, cb, ud);
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t c) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_unsubscribe_data(c);
    }
    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* ud,
                                            gn_subscription_id_t* out) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_subscribe_accept(cb, ud, out);
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t tok) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_unsubscribe_accept(tok);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<WsCarrierBridge*>(ctx)
            ->tcp->composer_listen_port(out);
    }
};

}  // namespace

template <>
struct LinkTraits<gn::link::ws::WsLink> {
    static constexpr const char* scheme = "ws";
    static std::shared_ptr<gn::link::ws::WsLink> make() {
        return std::make_shared<gn::link::ws::WsLink>();
    }
    static std::string listen_uri() { return "ws://127.0.0.1:0/"; }
    static std::string connect_uri(std::uint16_t port) {
        return "ws://127.0.0.1:" + std::to_string(port) + "/";
    }
    static bool wire_credentials(gn::link::ws::WsLink&,
                                  gn::link::ws::WsLink&) {
        return true;
    }
    /// Composer hook called by the conformance fixture before
    /// `make_api()` so WS's `query_extension_checked("gn.link.tcp")`
    /// during `set_host_api` resolves to a live TcpLink instance.
    static void install_carrier(ConformanceHost& host) {
        auto bridge = std::make_shared<WsCarrierBridge>();
        host.carrier_scheme = "tcp";
        host.carrier_vtable = &bridge->vtable;
        host.carrier_storage =
            std::shared_ptr<void>(std::move(bridge));
    }
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    WsLink,
    LinkTeardownConformance,
    ::testing::Types<gn::link::ws::WsLink>);

}  // namespace gn::test::link::conformance
