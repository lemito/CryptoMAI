cmake_minimum_required(VERSION 3.29.0)

set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "2182bf5c-ef0d-489a-91da-49dbc3090d2a")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};$VCPKG_ROOT/installed/x64-linux")

include(FetchContent)

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

find_package(Qt6 REQUIRED COMPONENTS Core Widgets LinguistTools Concurrent Sql QuickWidgets)
find_package(Qt6 REQUIRED COMPONENTS Core)

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

find_package(SQLite3 REQUIRED)
message(STATUS "SQLite3 version: ${SQLite3_VERSION}")

find_package(miniocpp CONFIG REQUIRED)

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

FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
                abseil
                GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
                GIT_TAG        20230802.1
)

set(ABSL_PROPAGATE_CXX_STD ON)
set(ABSL_ENABLE_INSTALL OFF)
set(ABSL_USE_EXTERNAL_GOOGLETEST OFF)
set(ABSL_FIND_GOOGLETEST OFF)

set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain")
set(VCPKG_ROOT $ENV{VCPKG_ROOT})
set(MINIO_ROOT ${VCPKG_ROOT}/installed/x64-linux)

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
        src/cypher/DiffieHelman/DiffieHelman.hpp src/cypher/DiffieHelman/rfc3526.hpp
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
qt_add_executable(CryptoGUI
        MANUAL_FINALIZATION
        src/GUI/utils.hpp
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
        src/GUI/contactlistitem.cpp
        src/GUI/contactlistitem.h
        src/GUI/choicedialog.cpp
        src/GUI/choicedialog.h
        src/GUI/dialogutils.cpp
        src/GUI/dialogutils.h
        src/GUI/joinchatdialog.cpp
        src/GUI/joinchatdialog.h
        src/GUI/createchatdialog.cpp
        src/GUI/createchatdialog.h
        src/GUI/chatstreamclient.cpp
        src/GUI/chatstreamclient.h
        src/GUI/databasemanager.cpp
        src/GUI/databasemanager.h
        src/GUI/messagestreamclient.h src/GUI/messagestreamclient.cpp
        src/GUI/messagesender.h src/GUI/messagesender.cpp
        src/GUI/messageassembler.h src/GUI/messageassembler.cpp
        src/GUI/test.qml
        src/GUI/resource.qrc
        src/GUI/ChatView.qml
        src/GUI/chatmanager.h src/GUI/chatmanager.cpp
        src/GUI/chat_structs.h
        src/GUI/chatstate.h src/GUI/chatstate.cpp
        src/GUI/AboutDialog.qml
        src/GUI/fileuploadmanager.h src/GUI/fileuploadmanager.cpp
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
# Заголовки
target_include_directories(CryptoGUI PRIVATE
    ${VCPKG_ROOT}/installed/x64-linux/include
    ${VCPKG_ROOT}/installed/x64-linux/include/minio-cpp
)
target_link_libraries(CryptoGUI PRIVATE
        # "${VCPKG_ROOT}/installed/x64-linux/lib/libminio.a"
        # "${VCPKG_ROOT}/installed/x64-linux/lib/libcurl.a"
        miniocpp::miniocpp
        absl::synchronization
        absl::flat_hash_map
        gRPC::grpc++
        protobuf::libprotobuf
        ChatProto
        CryptoSymmetricH CryptoRC6H CryptoLOKI97H CryptoDiffieHelmanH
        Qt6::Core Qt6::Widgets Qt6::Concurrent Qt6::Sql Qt6::QuickWidgets
)
target_link_libraries(CryptoGUI PRIVATE ${GMP_LIBRARY})
target_link_libraries(CryptoGUI PRIVATE SQLite::SQLite3)
target_link_libraries(CryptoGUI PRIVATE Qt6::Core)
target_compile_options(CryptoGUI PRIVATE -fPIC)
target_link_options(CryptoGUI PRIVATE -Wl,-rpath=${VCPKG_ROOT}/installed/x64-linux/lib)

qt_finalize_executable(CryptoGUI)

enable_testing()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(${COMMON_MODULE_FLAGS})
endif()

add_subdirectory(tests)
