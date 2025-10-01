add_executable(run_tests
        test_gcd.cpp
        test_symbols.cpp
)

target_link_libraries(run_tests
        PRIVATE
        Crypto
        GTest::gtest
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(run_tests)