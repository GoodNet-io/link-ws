// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/ws/tests/test_ws_conformance.cpp
/// @brief  Instantiates the SDK link teardown conformance suite
///         against `gn::link::ws::WsLink`.

#include <sdk/test/conformance/link_teardown.hpp>
#include <ws.hpp>

#include <memory>
#include <string>

namespace gn::test::link::conformance {

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
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    WsLink,
    LinkTeardownConformance,
    ::testing::Types<gn::link::ws::WsLink>);

}  // namespace gn::test::link::conformance
