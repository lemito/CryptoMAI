module;

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

export module cypher.loki97;

import cypher;

namespace meow::cypher::symm::_detailLOKI97 {

static constexpr uint64_t DELTA =
    0x9E3779B97F4A7C15ULL;  // (sqrt(5) - 1) * 2^63
static constexpr size_t ROUNDS = 16;
static constexpr size_t KEY_SCHEDULE_ROUNDS = 48;

static constexpr std::array<uint8_t, 64> P_TABLE = {
    56, 48, 40, 32, 24, 16, 8,  0, 57, 49, 41, 33, 25, 17, 9,  1,
    58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 28, 20, 12, 4, 61, 53, 45, 37, 29, 21, 13, 5,
    62, 54, 46, 38, 30, 22, 14, 6, 63, 55, 47, 39, 31, 23, 15, 7};

uint64_t load64(const std::vector<std::byte>& data, const size_t off) {
  if (off > data.size() || data.size() - off < 8) {
    throw std::out_of_range("off out of range");
  }
  uint64_t res = 0;
  for (int i = 0; i < 8; ++i) {
    res |= static_cast<uint64_t>(data[off + i]) << (56 - 8 * i);
  }
  return res;
}

void store64(std::vector<std::byte>& data, const size_t off,
             const uint64_t val) {
  if (off > data.size() || data.size() - off < 8) {
    throw std::out_of_range("off out of range");
  }
  for (int i = 0; i < 8; ++i) {
    data[off + i] = static_cast<std::byte>((val >> (56 - 8 * i)) & 0xFF);
  }
}

class LOKI97Core {
  static constexpr size_t S1_SIZE = 8192;
  static constexpr size_t S2_SIZE = 2048;

  std::array<uint8_t, S1_SIZE> S1;
  std::array<uint8_t, S2_SIZE> S2;

  constexpr void initSBoxes() {
    // странные преобразования в полях Галуа для создания S-box таблицы
    // ((x ^ 0x1FFF)^3 mod 0x2911) & 0xFF и живем GF(2^13)
    for (uint64_t i = 0; i < S1_SIZE; ++i) {
      const auto x = i ^ 0x1FFF;
      const uint64_t x2 = (x * x) ^ 0x1FFF;
      const uint64_t x3 = (x2 * x) ^ 0x1FFF;
      this->S1[i] = static_cast<uint8_t>(x3 % 0x2911) & 0xFF;
    }

    // S2: ((x ^ 0x7FF)^3 mod 0xAA7) & 0xFF и живем GF(2^11)
    for (uint64_t i = 0; i < S2_SIZE; ++i) {
      const uint64_t x = i ^ 0x7FF;
      const uint64_t x2 = (x * x) ^ 0x7FF;
      const uint64_t x3 = (x2 * x) ^ 0x7FF;
      this->S2[i] = static_cast<uint8_t>(x3 % 0xAA7) & 0xFF;
    }
  }

  // Мешает биты KP([Al|Ar],SKr) = [((Al & ~SKr)|(Ar & SKr)) | ((Ar & ~SKr)|(Al
  // & SKr))]
  static constexpr uint64_t KP(const uint64_t A, const uint32_t SKr) {
    const auto Al = static_cast<uint32_t>(A >> 32);
    const auto Ar = static_cast<uint32_t>(A & 0xFFFFFFFF);

    const uint32_t left = (Al & ~SKr) | (Ar & SKr);
    const uint32_t right = (Ar & ~SKr) | (Al & SKr);

    return (static_cast<uint64_t>(left) << 32) | right;
  }

  // расширяет ключик 64->96 ; при этом на группки по 13+11+13+11+11+13+11+13
  [[nodiscard]] static constexpr std::array<uint16_t, 8> E(const uint64_t in) {
    // [4-0,63-56|58-48|52-40|42-32|34-24|28-16|18-8|12-0]
    std::array<uint16_t, 8> res;

    res[0] = static_cast<uint16_t>(((in >> 56) & 0xFF) | ((in & 0x1F) << 8));
    res[1] = static_cast<uint16_t>(((in >> 48) & 0x7FF));
    res[2] = static_cast<uint16_t>(((in >> 40) & 0x1FFF));
    res[3] = static_cast<uint16_t>(((in >> 32) & 0x7FF));
    res[4] = static_cast<uint16_t>(((in >> 24) & 0x7FF));
    res[5] = static_cast<uint16_t>(((in >> 16) & 0x1FFF));
    res[6] = static_cast<uint16_t>(((in >> 8) & 0x7FF));
    res[7] = static_cast<uint16_t>((in & 0x1FFF));

    return res;
  }

  // на входе input+key (из стандарта). но по факту ток расширенный
  [[nodiscard]] constexpr uint64_t Sa(
      const std::array<uint16_t, 8>& exp) const {
    // [S1,S2,S1,S2,S2,S1,S2,S1] - порядок блоков
    uint64_t res = 0;

    for (int i = 0; i < 8; ++i) {
      uint8_t sbox_out;
      if (const uint8_t boxes[8] = {0, 1, 0, 1, 1, 0, 1, 0}; boxes[i] == 0) {
        sbox_out = S1[exp[i] & 0x1FFF];
      } else {
        sbox_out = S2[exp[i] & 0x7FF];
      }
      res |= static_cast<uint64_t>(sbox_out) << (8 * (7 - i));
    }

    return res;
  }

  // а тут только входной блок
  [[nodiscard]] constexpr uint64_t Sb(const uint64_t in) const {
    uint64_t res = 0;

    for (int i = 0; i < 8; ++i) {
      const auto byte_val = static_cast<uint8_t>((in >> (8 * (7 - i))) & 0xFF);
      uint8_t sbox_out;
      if (const uint8_t boxes[8] = {1, 1, 0, 0, 1, 1, 0, 0}; boxes[i] == 0) {
        sbox_out = S1[byte_val];
      } else {
        sbox_out = S2[byte_val];
      }
      res |= static_cast<uint64_t>(sbox_out) << (8 * (7 - i));
    }

    return res;
  }

  // применение перестановки
  [[nodiscard]] constexpr uint64_t P(const uint64_t in) const {
    uint64_t res = 0;
    for (int i = 0; i < 64; ++i) {
      if (in & (1ULL << i)) {
        res |= (1ULL << P_TABLE[i]);
      }
    }
    return res;
  }

 public:
  LOKI97Core() { initSBoxes(); }

  // f(A,B) = Sb(P(Sa(E(KP(A,B)))),B)
  [[nodiscard]] constexpr uint64_t F(const uint64_t A, const uint64_t B) const {
    const auto SKr = static_cast<uint32_t>(B & 0xFFFFFFFF);

    const uint64_t kp_res = KP(A, SKr);
    auto expanded = E(kp_res);
    const uint64_t sa_res = Sa(std::move(expanded));
    const uint64_t p_res = P(sa_res);
    const uint64_t sb_res = Sb(p_res);

    return sb_res;
  }
};

class LOKI97GenRoundKey : public IGenRoundKey, public LOKI97Core {
  std::array<uint64_t, KEY_SCHEDULE_ROUNDS> subkeys;

  void keySchedule(const std::vector<std::byte>& key) {
    if (key.empty()) {
      throw std::runtime_error("key is empty in keySchedule");
    }
    // ключик делится на 4 части, но если он маленький - часть через функцию
    uint64_t K40, K30, K20, K10;

    switch (key.size()) {
      case 32: {
        K40 = load64(key, 0);
        K30 = load64(key, 8);
        K20 = load64(key, 16);
        K10 = load64(key, 24);
      } break;
      case 24: {
        K40 = load64(key, 0);
        K30 = load64(key, 8);
        K20 = load64(key, 16);
        K10 = F(K40, K30);
      } break;
      case 16: {
        K40 = load64(key, 0);
        K30 = load64(key, 8);
        K20 = F(K30, K40);
        K10 = F(K40, K30);
      } break;
      default:
        throw std::runtime_error("error - no such size");
    }

    uint64_t K4 = K40, K3 = K30, K2 = K20, K1 = K10;

    for (size_t i = 1; i <= KEY_SCHEDULE_ROUNDS; ++i) {
      const uint64_t gi = F(K1 + K3 + (DELTA * i), K2);
      const uint64_t SKi = K4 ^ gi;

      subkeys[i - 1] = SKi;

      std::tie(K4, K3, K2, K1) = std::tuple(K3, K2, K1, SKi);
    }
  }

 public:
  explicit LOKI97GenRoundKey() : IGenRoundKey(ROUNDS), subkeys() {}

  std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) override {
    if (inputKey.empty() || inputKey.size() > 32) {
      throw std::invalid_argument(
          "LOKI97 supports only 128, 192, or 256-bit keys");
    }

    if (inputKey.size() != 16 && inputKey.size() != 24 &&
        inputKey.size() != 32) {
      throw std::invalid_argument(
          "LOKI97 key must be exactly 128, 192, or 256 bits");
    }

    try {
      keySchedule(inputKey);

      std::vector<std::vector<std::byte>> result;
      result.reserve(KEY_SCHEDULE_ROUNDS);

      for (size_t i = 0; i < KEY_SCHEDULE_ROUNDS; ++i) {
        std::vector<std::byte> key_bytes(8);
        store64(key_bytes, 0, subkeys[i]);
        result.push_back(std::move(key_bytes));
      }

      return result;
    } catch (const std::exception& e) {
      throw std::runtime_error(std::string("Key schedule failed: ") + e.what());
    }
  }
};
}  // namespace meow::cypher::symm::_detailLOKI97

export namespace meow::cypher::symm::LOKI97 {

class LOKI97 final : public ISymmetricCypher,
                     public _detailLOKI97::LOKI97GenRoundKey {
 public:
  LOKI97() { _blockSize = 16; }

  static size_t blockSize() { return 16; }

  void setRoundKeys(const std::vector<std::byte>& encryptionKey) override {
    _roundKeys = genRoundKeys(encryptionKey);
  }

  [[nodiscard]] std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    if (in.size() != 16) {
      throw std::invalid_argument("Block size must be 128 bits");
    }
    if (_roundKeys.size() != 48) {
      throw std::logic_error("Round keys not set");
    }

    std::vector<std::byte> res(16);

    uint64_t L = _detailLOKI97::load64(in, 0);
    uint64_t R = _detailLOKI97::load64(in, 8);

    for (size_t i = 0; i < 16; ++i) {
      const uint64_t SK3i_2 = _detailLOKI97::load64(_roundKeys[3 * i + 2], 0);
      const uint64_t SK3i_1 = _detailLOKI97::load64(_roundKeys[3 * i + 1], 0);
      const uint64_t SK3i = _detailLOKI97::load64(_roundKeys[3 * i], 0);

      std::tie(L, R) = std::tuple(R + SK3i, L ^ F(R, SK3i_1 + SK3i_2));
    }

    _detailLOKI97::store64(res, 0, L);
    _detailLOKI97::store64(res, 8, R);

    return res;
  }

  [[nodiscard]] std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    if (in.size() != 16) {
      throw std::invalid_argument("Block size must be 128 bits");
    }
    if (_roundKeys.size() != 48) {
      throw std::logic_error("Round keys not set");
    }

    std::vector<std::byte> out(16);

    uint64_t L = _detailLOKI97::load64(in, 0);
    uint64_t R = _detailLOKI97::load64(in, 8);

    for (int i = 15; i >= 0; --i) {
      const uint64_t SK3i_2 = _detailLOKI97::load64(_roundKeys[3 * i + 2], 0);
      const uint64_t SK3i_1 = _detailLOKI97::load64(_roundKeys[3 * i + 1], 0);
      const uint64_t SK3i = _detailLOKI97::load64(_roundKeys[3 * i], 0);

      std::tie(L, R) = std::tuple(R ^ F(L - SK3i, SK3i_1 + SK3i_2), L - SK3i);
    }

    _detailLOKI97::store64(out, 0, L);
    _detailLOKI97::store64(out, 8, R);

    return out;
  }
};
}  // namespace meow::cypher::symm::LOKI97