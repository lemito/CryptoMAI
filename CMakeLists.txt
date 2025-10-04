cmake_minimum_required(VERSION 3.29.3...3.32)

set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API ON)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fimplicit-modules -fimplicit-module-maps -stdlib=libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fimplicit-modules -stdlib=libc++")

project(CryptoMAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
#set(CMAKE_CXX_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/cmodulecache)

find_package(Boost REQUIRED)
find_library(GMP_LIBRARY gmp)
#find_package(GMP REQUIRED)

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

#add_executable(Crypto
##        Crypto.cpp
##        Crypto.h
#        src/perestanovki.cpp
#)
add_library(Crypto STATIC
        src/perestanovki.cpp
)

target_link_libraries(Crypto PRIVATE ${GMP_LIBRARY})
target_include_directories(Crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_sources(Crypto PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/cypher.cppm
        src/math/primary/PrimaryTests.cppm
        src/math/math.cppm
        src/cypher/RSA/RSA.cppm
        src/cypher/RSA/BadRSA.cppm
)

target_compile_features(Crypto PRIVATE cxx_std_23)
# Remove or modify these flags
target_compile_options(Crypto PRIVATE
        -fmodules
#        -fbuiltin-module-map
        -fprebuilt-module-path=${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_options(Crypto PRIVATE -fno-modules)
if (MSVC)
    target_compile_options(Crypto PRIVATE /std:c++latest)
else ()
    target_compile_options(Crypto PRIVATE -std=c++23)
endif ()

enable_testing()
add_subdirectory(tests)