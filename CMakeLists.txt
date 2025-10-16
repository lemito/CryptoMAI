cmake_minimum_required(VERSION 3.29.3...3.32)

set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmodules -fbuiltin-module-map -fimplicit-modules -stdlib=libc++")

project(CryptoMAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED)
find_library(GMP_LIBRARY gmp)

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(CryptoMath STATIC)
add_library(CryptoRSA STATIC)
add_library(CryptoSymmetric STATIC)
add_library(Crypto INTERFACE)

target_compile_features(CryptoMath PRIVATE cxx_std_23)
target_sources(CryptoMath PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/math/primary/PrimaryTests.cppm
        src/math/math.cppm
)
target_link_libraries(CryptoMath PRIVATE ${GMP_LIBRARY})
target_include_directories(CryptoMath PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_features(CryptoRSA PRIVATE cxx_std_23)
target_sources(CryptoRSA PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/RSA/RSA.cppm
        src/cypher/RSA/BadRSA.cppm
        src/cypher/RSA/attack/WiennerAttack.cppm
)
target_link_libraries(CryptoRSA PUBLIC CryptoMath)

target_compile_features(CryptoSymmetric PRIVATE cxx_std_23)
target_sources(CryptoSymmetric PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/permutate.cppm
        src/cypher/SymmetricAlgorithms/cypher.cppm
        src/cypher/SymmetricAlgorithms/FeistelNet.cppm
)
target_link_libraries(CryptoSymmetric PUBLIC CryptoMath)

target_link_libraries(Crypto INTERFACE
        CryptoMath
        CryptoRSA
        CryptoSymmetric
)

foreach (target CryptoMath CryptoRSA CryptoSymmetric)
    target_compile_options(${target} PRIVATE
            -fmodules
            -fbuiltin-module-map
            -fimplicit-modules
            -stdlib=libc++
            -fprebuilt-module-path=${CMAKE_CURRENT_BINARY_DIR}
    )
endforeach ()

enable_testing()
add_subdirectory(tests)

add_executable(experiments tests/experiments/experiments.cpp)

if (Boost_FOUND)
    include_directories (SYSTEM ${Boost_INCLUDE_DIR})
    target_link_libraries (experiments ${Boost_LIBRARIES})
endif ()