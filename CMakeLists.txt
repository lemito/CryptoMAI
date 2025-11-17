cmake_minimum_required(VERSION 3.29.3...3.32)

set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "2182bf5c-ef0d-489a-91da-49dbc3090d2a")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_SCAN_FOR_MODULES ON)

project(CryptoMAI LANGUAGES CXX)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(MODULE_CACHE_DIR "${CMAKE_BINARY_DIR}/global_module_cache")
    file(MAKE_DIRECTORY ${MODULE_CACHE_DIR})

    execute_process(
            COMMAND ${CMAKE_CXX_COMPILER} -print-resource-dir
            OUTPUT_VARIABLE CLANG_RESOURCE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
    )

    set(MODULE_MAP_FLAG "")
    if (CLANG_RESOURCE_DIR)
        set(MODULE_MAP_PATH "${CLANG_RESOURCE_DIR}/include/module.modulemap")
        if (EXISTS "${MODULE_MAP_PATH}")
            set(MODULE_MAP_FLAG "-fmodule-map-file=${MODULE_MAP_PATH}")
            message(STATUS "Using Clang module map: ${MODULE_MAP_PATH}")
        endif ()
    endif ()

    set(COMMON_MODULE_FLAGS
            -fmodules
            -fno-implicit-modules
            -fmodules-cache-path=${MODULE_CACHE_DIR}
            -fimplicit-modules
            -fimplicit-module-maps
            ${MODULE_MAP_FLAG}
            -Xclang -fmodules-validate-system-headers
            -pthread
    )

    set(SYSTEM_MODULE_PREBUILD_FLAGS
        -fmodules
        -fno-implicit-modules
        -fmodules-cache-path=${MODULE_CACHE_DIR}
        -fimplicit-modules
        -fimplicit-module-maps
        ${MODULE_MAP_FLAG}
        -Xclang -emit-module
        -Xclang -fmodules-validate-system-headers
        -c
        -x c++
        -o ${MODULE_CACHE_DIR}/system_modules.pcm
        /dev/null
    )

    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} ${SYSTEM_MODULE_PREBUILD_FLAGS}
        ERROR_QUIET
        RESULT_VARIABLE PREBUILD_RESULT
    )

    if(NOT MODULE_MAP_FLAG)
        message(WARNING "Clang module map not found - modules may fail to build")
    endif()
endif ()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets LinguistTools)

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

add_library(ChatProto ${PROTO_DIR}/chat.proto)
target_link_libraries(ChatProto PUBLIC gRPC::grpc++)

protobuf_generate(TARGET ChatProto)
protobuf_generate(
        TARGET ChatProto
        LANGUAGE grpc
        PLUGIN protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
        PLUGIN_OPTIONS generate_mock_code=true
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
)

target_include_directories(ChatProto PUBLIC
        ${PROTO_GEN_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

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
add_library(CryptoRC6 STATIC)
add_library(CryptoLOKI97 STATIC)
add_library(CryptoDiffieHelman STATIC)
add_library(CryptoMathH SHARED)
add_library(CryptoSymmetricH SHARED)
add_library(CryptoRC6H SHARED)
add_library(CryptoLOKI97H SHARED)
add_library(CryptoDiffieHelmanH SHARED)

foreach (MATH_LIB CryptoMath CryptoRSA CryptoSymmetric CryptoDES CryptoDEAL
        CryptoGaloisFieldPoly Rijndael CryptoRC6 CryptoLOKI97 CryptoDiffieHelman)
    target_compile_features(${MATH_LIB} PRIVATE cxx_std_23)
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${MATH_LIB} PRIVATE ${COMMON_MODULE_FLAGS})
    endif ()
endforeach ()

target_sources(CryptoMath PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/math/primary/PrimaryTests.cppm
        src/math/math.cppm
)
target_link_libraries(CryptoMath PRIVATE ${GMP_LIBRARY})

target_sources(CryptoMathH PUBLIC
        src/math/primary/PrimaryTests.hpp
        src/math/math.hpp
)
target_link_libraries(CryptoMathH PRIVATE ${GMP_LIBRARY})

target_include_directories(CryptoMath PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_include_directories(CryptoMathH PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_sources(CryptoRSA PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/RSA/RSA.cppm
        src/cypher/RSA/BadRSA.cppm
        src/cypher/RSA/attack/WiennerAttack.cppm
)
target_link_libraries(CryptoRSA PUBLIC CryptoMath)

target_sources(CryptoSymmetric PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/utils.cppm
        src/cypher/SymmetricAlgorithms/cypher.cppm
        src/cypher/SymmetricAlgorithms/FeistelNet.cppm
)
target_link_libraries(CryptoSymmetric PUBLIC CryptoMath)

target_sources(CryptoSymmetricH PUBLIC
        src/cypher/SymmetricAlgorithms/utils.hpp
        src/cypher/SymmetricAlgorithms/cypher.hpp
)
target_link_libraries(CryptoSymmetricH PUBLIC CryptoMathH)

target_include_directories(CryptoSymmetricH PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_sources(CryptoDES PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/DES/des_tables.cppm
        src/cypher/SymmetricAlgorithms/DES/DES.cppm
)
target_link_libraries(CryptoDES PUBLIC CryptoSymmetric)

target_sources(CryptoDEAL PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/DEAL/DEAL.cppm
)
target_link_libraries(CryptoDEAL PUBLIC CryptoSymmetric CryptoDES)

target_sources(CryptoGaloisFieldPoly PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/math/GaloisFieldPoly.cppm
)

target_sources(Rijndael PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/Rijndael/Rijndael.cppm
)
target_link_libraries(Rijndael PUBLIC CryptoSymmetric CryptoGaloisFieldPoly)

target_sources(CryptoLOKI97 PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/LOKI97/loki97.cppm
)
target_link_libraries(CryptoLOKI97 PUBLIC CryptoSymmetric)

target_sources(CryptoRC6 PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/SymmetricAlgorithms/RC6/rc6.cppm
)
target_link_libraries(CryptoRC6 PUBLIC CryptoSymmetric)

target_sources(CryptoDiffieHelman PUBLIC
        FILE_SET CXX_MODULES TYPE CXX_MODULES FILES
        src/cypher/DiffieHelman/DiffieHelman.cppm
)
target_link_libraries(CryptoDiffieHelman PUBLIC CryptoMath)

target_sources(CryptoLOKI97H PUBLIC
        src/cypher/SymmetricAlgorithms/LOKI97/loki97.hpp
)
target_link_libraries(CryptoLOKI97H PUBLIC CryptoSymmetricH)
target_include_directories(CryptoLOKI97H PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_sources(CryptoRC6H PUBLIC
        src/cypher/SymmetricAlgorithms/RC6/rc6.hpp
)
target_link_libraries(CryptoRC6H PUBLIC CryptoSymmetricH)
target_include_directories(CryptoRC6H PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_sources(CryptoDiffieHelmanH PUBLIC
        src/cypher/DiffieHelman/DiffieHelman.hpp
)
target_link_libraries(CryptoDiffieHelmanH PUBLIC CryptoMathH)
target_include_directories(CryptoDiffieHelmanH PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_library(Crypto STATIC
        include/debug.h)
target_compile_features(Crypto PRIVATE cxx_std_23)

target_link_libraries(Crypto PUBLIC
        CryptoMath
        CryptoRSA
        CryptoSymmetric
        CryptoDES
        CryptoDEAL
        CryptoGaloisFieldPoly
        Rijndael
        CryptoLOKI97
        CryptoRC6
        CryptoDiffieHelman
)

# GUI 
set(GUI_SOURCES
        src/GUI/main.cpp
        src/GUI/mainwindow.cpp
        src/GUI/mainwindow.h
        src/GUI/mainwindow.ui
        src/GUI/logindialog.cpp
        src/GUI/logindialog.h
        src/GUI/logindialog.ui
        src/GUI/contactsdialog.cpp
        src/GUI/contactsdialog.h
        src/GUI/contactsdialog.ui
        src/GUI/sessionmanager.cpp
        src/GUI/sessionmanager.h
)

qt_add_executable(CryptoGUI
        MANUAL_FINALIZATION
        ${GUI_SOURCES}
)

target_compile_features(CryptoGUI PUBLIC cxx_std_23)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(CryptoGUI PRIVATE -fno-modules)
endif ()

target_include_directories(CryptoGUI PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/GUI
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set(TS_FILES src/GUI/CryptoGUI_ru_RU.ts)
qt_create_translation(QM_FILES ${CMAKE_CURRENT_SOURCE_DIR} ${TS_FILES})

target_link_libraries(CryptoGUI PRIVATE
        gRPC::grpc++
        protobuf::libprotobuf
        ChatProto
        CryptoSymmetricH CryptoRC6H CryptoLOKI97H CryptoDiffieHelmanH
        Qt6::Widgets
)

qt_finalize_executable(CryptoGUI)

enable_testing()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(${COMMON_MODULE_FLAGS})
endif()

add_subdirectory(tests)
