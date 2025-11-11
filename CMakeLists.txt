cmake_minimum_required(VERSION 3.29.3...3.32)
#
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pg -g")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "2182bf5c-ef0d-489a-91da-49dbc3090d2a")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API ON)
# set_property(DIRECTORY PROPERTY CXX_MODULE_CACHE_DIR "${CMAKE_BINARY_DIR}/module-cache")
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    #     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmodules-cache-path=${CMAKE_BINARY_DIR}/module_cache")

    file(REMOVE_RECURSE ${CMAKE_BINARY_DIR}/module_cache)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/module_cache)
endif ()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmodules -fbuiltin-module-map -fimplicit-modules -stdlib=libc++ -fprebuilt-module-path=${CMAKE_CURRENT_BINARY_DIR} -pthread ")

project(CryptoMAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
#set(CMAKE_CXX_MODULE_STD ON)

find_package(Boost REQUIRED)
find_library(GMP_LIBRARY gmp)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

find_package(Protobuf REQUIRED)
message(STATUS "Protobuf version: ${Protobuf_VERSION}")
message(STATUS "Protobuf include dir: ${Protobuf_INCLUDE_DIRS}")
message(STATUS "Protobuf libraries: ${Protobuf_LIBRARIES}")

find_package(gRPC REQUIRED)
message(STATUS "gRPC version: ${gRPC_VERSION}")
message(STATUS "gRPC include dir: ${gRPC_INCLUDE_DIRS}")
message(STATUS "gRPC libraries: ${gRPC_LIBRARIES}")

set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${GENERATED_DIR})

add_library(CypherProto ${PROTO_DIR}/cypher.proto)
target_link_libraries(CypherProto PUBLIC gRPC::grpc++)

protobuf_generate(TARGET CypherProto)
protobuf_generate(
        TARGET CypherProto
        LANGUAGE grpc
        PLUGIN protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
        PLUGIN_OPTIONS generate_mock_code=true
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
)


target_include_directories(CypherProto PUBLIC
        ${PROTO_GEN_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(CypherProto PUBLIC gRPC::grpc++)

#protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_DIR}/cypher.proto)

# set(PROTO_FILE ${PROTO_DIR}/cypher.proto)
# set(PROTO_SRCS "${GENERATED_DIR}/cypher.pb.cc")
# set(PROTO_HDRS "${GENERATED_DIR}/cypher.pb.h")
# set(GRPC_SRCS "${GENERATED_DIR}/cypher.grpc.pb.cc")
# set(GRPC_HDRS "${GENERATED_DIR}/cypher.grpc.pb.h")

# add_custom_command(
#         OUTPUT ${PROTO_SRCS} ${PROTO_HDRS}
#         COMMAND ${Protobuf_PROTOC_EXECUTABLE}
#         ARGS
#         --cpp_out=${GENERATED_DIR}
#         -I ${PROTO_DIR}
#         ${PROTO_FILE}
#         DEPENDS ${PROTO_FILE} ${Protobuf_PROTOC_EXECUTABLE}
#         COMMENT "Generating protobuf code"
# )

# add_custom_command(
#         OUTPUT ${GRPC_SRCS} ${GRPC_HDRS}
#         COMMAND ${Protobuf_PROTOC_EXECUTABLE}
#         ARGS
#         --grpc_out=${GENERATED_DIR}
#         --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
#         -I ${PROTO_DIR}
#         ${PROTO_FILE}
#         DEPENDS ${PROTO_FILE} ${Protobuf_PROTOC_EXECUTABLE} gRPC::grpc_cpp_plugin
#         COMMENT "Generating gRPC code"
# )

# add_custom_target(generate_proto_files ALL
#         DEPENDS ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
# )

# include_directories(
#         ${CMAKE_CURRENT_SOURCE_DIR}
#         ${GENERATED_DIR}
#         ${Protobuf_INCLUDE_DIRS}
#         ${gRPC_INCLUDE_DIRS}
# )
#find_program(CLANG_TIDY_EXE NAMES "clang-tidy" REQUIRED)
#set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "-checks=-*,modernize-*,performance-*,cppcoreguidelines-*")

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
add_library(CryptoDES STATIC)
add_library(CryptoDEAL STATIC)
add_library(CryptoGaloisFieldPoly STATIC)
add_library(Rijndael STATIC)
add_library(Crypto INTERFACE
        include/debug.h)

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
        src/cypher/SymmetricAlgorithms/utils.cppm
        src/cypher/SymmetricAlgorithms/cypher.cppm
        src/cypher/SymmetricAlgorithms/FeistelNet.cppm
)
target_link_libraries(CryptoSymmetric PUBLIC CryptoMath)

target_compile_features(CryptoDES PRIVATE cxx_std_23)
target_sources(CryptoDES PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/DES/des_tables.cppm
        src/cypher/SymmetricAlgorithms/DES/DES.cppm
)
target_link_libraries(CryptoDES PUBLIC CryptoSymmetric)

target_compile_features(CryptoDEAL PRIVATE cxx_std_23)
target_sources(CryptoDEAL PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/DEAL/DEAL.cppm
)
target_link_libraries(CryptoDEAL PUBLIC CryptoSymmetric CryptoDES)

target_compile_features(CryptoGaloisFieldPoly PRIVATE cxx_std_23)
target_sources(CryptoGaloisFieldPoly PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/math/GaloisFieldPoly.cppm
)
target_link_libraries(CryptoGaloisFieldPoly PUBLIC)

target_compile_features(Rijndael PRIVATE cxx_std_23)
target_sources(Rijndael PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/Rijndael/Rijndael.cppm
)
target_link_libraries(Rijndael PUBLIC CryptoSymmetric CryptoGaloisFieldPoly)

target_link_libraries(Crypto INTERFACE
        CryptoMath
        CryptoRSA
        CryptoSymmetric
        CryptoDES
        CryptoDEAL
        CryptoGaloisFieldPoly
        Rijndael
)

foreach (target CryptoMath CryptoRSA CryptoSymmetric CryptoDES CryptoDEAL)
    target_compile_options(${target} PRIVATE
            -fmodules
            -fbuiltin-module-map
            -fimplicit-modules
            -stdlib=libc++
            -fprebuilt-module-path=${CMAKE_CURRENT_BINARY_DIR}
            -pthread
    )
    #   set_target_properties(${target} PROPERTIES CXX_STANDART 23 CXX_STANDART_REQUIRED ON CXX_EXTENSIONS OFF CXX_MODULE_STD 1)
endforeach ()

enable_testing()
add_subdirectory(tests)
add_subdirectory("src/server")

add_executable(experiments tests/experiments/experiments.cpp)

if (Boost_FOUND)
    include_directories(SYSTEM ${Boost_INCLUDE_DIR})
    target_link_libraries(experiments ${Boost_LIBRARIES})
endif ()
#set_target_properties(CryptoSymmetric PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
