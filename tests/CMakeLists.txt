add_executable(test_gcd
        test_gcd.cpp
)
target_link_libraries(test_gcd PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_symbols
        test_symbols.cpp
)
target_link_libraries(test_symbols PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_fermat
        test_fermat.cpp
)
target_link_libraries(test_fermat PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_solovey_strassen
        test_solovey_strassen.cpp
)
target_link_libraries(test_solovey_strassen PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_miller_rabin
        test_miller_rabin.cpp
)
target_link_libraries(test_miller_rabin PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_rsa
        test_rsa.cpp
)
target_link_libraries(test_rsa PRIVATE Crypto GTest::gtest GTest::gtest_main)

#add_executable(test_permutate
#        test_permutate.cpp
#)
#target_link_libraries(test_permutate PRIVATE Crypto GTest::gtest GTest::gtest_main)

add_executable(test_WiennerAttack test_WiennerAttack.cpp)
target_link_libraries(test_WiennerAttack PRIVATE Crypto GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(test_gcd)
gtest_discover_tests(test_symbols)
gtest_discover_tests(test_fermat)
gtest_discover_tests(test_miller_rabin)
gtest_discover_tests(test_solovey_strassen)
gtest_discover_tests(test_rsa)
gtest_discover_tests(test_WiennerAttack)
#gtest_discover_tests(test_permutate)
