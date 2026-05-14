# WebSocket link plugin unit tests — MIT.
include(GoogleTest)

set(_ws_test_sources test_ws.cpp test_ws_conformance.cpp)
set(_ws_test_carriers goodnet_tcp_objects)
# `wss://` exercises a TLS carrier layered on top of the TCP carrier —
# only wire it up when the TLS plugin is present in the workspace.
if(TARGET goodnet_tls_objects)
    list(APPEND _ws_test_sources test_wss.cpp)
    list(APPEND _ws_test_carriers goodnet_tls_objects)
endif()

add_executable(test_ws ${_ws_test_sources})
# The carrier-mode WS plugin links its tests against the TCP (and
# optionally TLS) plugin objects so the in-tree test fixture can stand
# up a real `gn.link.tcp` / `gn.link.tls` extension surface and drive a
# full WS handshake + framing roundtrip without spinning up the
# kernel-side plugin loader.
target_link_libraries(test_ws PRIVATE
    GoodNet::sdk
    goodnet_ws_objects
    ${_ws_test_carriers}
    asio::asio
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_include_directories(test_ws PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tcp)
if(TARGET goodnet_tls_objects)
    target_include_directories(test_ws PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../tls)
    if(TARGET OpenSSL::SSL)
        target_link_libraries(test_ws PRIVATE
            OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(TARGET PkgConfig::SODIUM)
        target_link_libraries(test_ws PRIVATE PkgConfig::SODIUM)
    endif()
endif()
target_compile_features(test_ws PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_ws)
endif()
gtest_discover_tests(test_ws
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
