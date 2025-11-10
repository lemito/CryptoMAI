add_executable(Server src/main.cpp)
target_compile_options(Server PRIVATE
        -fmodules
        -fbuiltin-module-map
        -fimplicit-modules
        -stdlib=libc++
        -fprebuilt-module-path=${CMAKE_CURRENT_BINARY_DIR}
        -pthread
)

target_link_libraries(Server PRIVATE
        CryptoSymmetric
        CryptoDES
        CryptoDEAL
        Rijndael
        ${GMP_LIBRARY}
        Threads::Threads
        CypherProto
)