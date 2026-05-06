# WebSocket link plugin unit tests — MIT.
include(GoogleTest)

add_executable(test_ws test_ws.cpp)
target_link_libraries(test_ws PRIVATE
    GoodNet::sdk
    goodnet_ws_objects
    asio::asio
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_ws PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_ws)
endif()
gtest_discover_tests(test_ws
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
