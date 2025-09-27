cmake_minimum_required(VERSION 3.29)

project(CryptoMAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/cmodulecache)

add_executable(Crypto
        Crypto.cpp
        Crypto.h
        src/perestanovki.cpp
)

target_sources(Crypto PRIVATE
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher.cppm
)

target_compile_features(Crypto PRIVATE cxx_std_23)

if(MSVC)
    target_compile_options(Crypto PRIVATE /std:c++latest)
else()
    target_compile_options(Crypto PRIVATE -std=c++23)
endif()
