#pragma once

#include <string>

static constexpr std::string SESSION_TOKEN_HEADER = "x-session-token";

template <typename T = void>
void safe_delete(T*& ptr) noexcept {
  if (ptr != nullptr) {
    delete ptr;
    ptr = nullptr;
  }
}