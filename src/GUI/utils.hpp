#pragma once

#include <cstdint>
#include <string>

static constexpr std::uint16_t CLEANUP_INTERVAL = 30000;
static constexpr std::uint32_t ASSEMBLY_INTERVAL = 120000;

static constexpr std::string GRPC_URL = "localhost:50051";

static constexpr std::string MINIO_URL = "127.0.0.1:9000";
static constexpr std::string MINIO_USR = "minioadmin";
static constexpr std::string MINIO_PASS = "minioadmin";

static constexpr std::string SESSION_TOKEN_HEADER = "x-session-token";
static constexpr std::uint32_t CHUNK_SIZE = 64 * 1024;

template <typename T = void>
void safe_delete(T*& ptr) noexcept {
  if (ptr != nullptr) {
    delete ptr;
    ptr = nullptr;
  }
}
