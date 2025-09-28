cmake_minimum_required(VERSION 3.29)

project(CryptoMAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/cmodulecache)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fmodules)
endif()

find_package(Boost REQUIRED)
find_library(GMP_LIBRARY gmp)
#find_package(GMP REQUIRED)

add_executable(Crypto
    Crypto.cpp
    Crypto.h
    src/perestanovki.cpp
)

target_link_libraries(Crypto PRIVATE ${GMP_LIBRARY})
target_include_directories(Crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_sources(Crypto PRIVATE
    FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
    src/cypher/cypher.cppm src/math/primary/PrimaryTests.cppm src/math/math.cppm
)

target_compile_features(Crypto PRIVATE cxx_std_23)

if(MSVC)
    target_compile_options(Crypto PRIVATE /std:c++latest)
else()
    target_compile_options(Crypto PRIVATE -std=c++23)
endif()
