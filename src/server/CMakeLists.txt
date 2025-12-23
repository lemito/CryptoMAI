cmake_minimum_required(VERSION 3.29.3...3.32)
project(CryptoServer)

find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(Threads REQUIRED)  # For pthread

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(Server src/main.cpp)

target_link_libraries(Server PRIVATE Threads::Threads)

target_link_libraries(Server PRIVATE
        CypherProto         
        CryptoSymmetric
        CryptoDES
        CryptoDEAL
        Rijndael
        CryptoMath
        CryptoGaloisFieldPoly
        gRPC::grpc++        
        -lc++abi
)