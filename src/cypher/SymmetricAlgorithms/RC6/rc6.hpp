/**
 * https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf?spm=a2ty_o01.29997173.0.0.78cec921twWyWp&file=RRSY98.pdf
 */
#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

#include "cypher.hpp"


namespace meow::cypher::symm::_detailRC6 {
constexpr uint32_t cycleLeft(const uint32_t num, uint32_t shift) {
  shift %= 32;
  return (num << shift) | (num >> ((32 - shift)));
}

constexpr uint32_t cycleRight(const uint32_t num, uint32_t shift) {
  shift %= 32;
  return (num >> shift) | (num << ((32 - shift)));
}

class RC6GenRoundKey final : public IGenRoundKey {
  static constexpr int32_t w = 32;  // размер слова (блоков 4 => длина блока
  // 128бит) odd - округление

  static constexpr uint32_t P =
      0xB7E15163;  // odd((e - 1) * 2^w); e - экспонента ~ 2.718
  static constexpr uint32_t Q =
      0x9E3779B9;  // odd((fi - 1) * 2^w) fi - золотое сечение ~ 1.618

 public:
  std::vector<uint32_t> _S{};  // таблица ключей, но в числах

  explicit RC6GenRoundKey(const size_t RoundCnt) : IGenRoundKey(RoundCnt) {}
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] constexpr std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) override {
    assert(roundCnt == 20);
    static_assert(w == 32, "w!=32");
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    if (inputKey.size() != 16 && inputKey.size() != 24 &&
        inputKey.size() != 32) {
      throw std::runtime_error(
          "ключ должен быть 16/24/32 байт == 128/192/256 бит");
    }

    const auto bytesToWords = [](const std::vector<std::byte>& bytes) {
      std::vector<uint32_t> words;
      words.reserve(bytes.size() / 4);

      for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t word =
            static_cast<uint8_t>(bytes[i]) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 1])) << 8) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 2])) << 16) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 3])) << 24);

        if constexpr (std::endian::native == std::endian::big) {
          word = std::byteswap(word);
        }
        words.push_back(word);
      }
      return words;
    };

    auto L = bytesToWords(inputKey);
    const std::size_t c = L.size();

    _S.clear();
    _S.resize(2 * roundCnt + 4);

    _S[0] = P;
    for (size_t i = 1; i < _S.size(); ++i) {
      _S[i] = _S[i - 1] + Q;
    }

    uint32_t A = 0;
    uint32_t B = 0;
    std::size_t i = 0;
    std::size_t j = 0;

    const size_t n = 3 * std::max(_S.size(), c);
    for (std::size_t k = 0; k < n; ++k) {
      A = _S[i] = utils::ShiftBytesLeft(_S[i] + A + B, 3, 32);
      B = L[j] =
          utils::ShiftBytesLeft(L[j] + A + B, static_cast<int>(A + B) % 32, 32);

      i = (i + 1) % _S.size();
      j = (j + 1) % c;
    }

    std::vector<std::vector<std::byte>> res;
    res.reserve(_S.size());

    for (const uint32_t word : _S) {
      std::vector<std::byte> tmp(4);
      tmp[0] = static_cast<std::byte>(word & 0xFF);
      tmp[1] = static_cast<std::byte>((word >> 8) & 0xFF);
      tmp[2] = static_cast<std::byte>((word >> 16) & 0xFF);
      tmp[3] = static_cast<std::byte>((word >> 24) & 0xFF);
      res.push_back(std::move(tmp));
    }

    return res;  // по апи возвращаем ключ в байтах (пустой не подойдет)
  }
};
}  // namespace meow::cypher::symm::_detailRC6

namespace meow::cypher::symm::RC6 {
class RC6 final : public ISymmetricCypher {
  _detailRC6::RC6GenRoundKey _keyGen;

 public:
  RC6() : _keyGen(20) { _blockSize = 128 / 8; }

  constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) override {
    _roundKeys = _keyGen.genRoundKeys(encryptionKey);
  }

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    if (in.size() != 16) {
      throw std::runtime_error("block must be 128bit");
    }
    std::array<std::byte, 16> raw_state;
    std::memcpy(raw_state.data(), in.data(), 16);

    auto words = std::bit_cast<std::array<uint32_t, 4>>(raw_state);

    if constexpr (std::endian::native == std::endian::big) {
      for (auto& w : words) w = std::byteswap(w);
    }

    uint32_t A = words[0];
    uint32_t B = words[1];
    uint32_t C = words[2];
    uint32_t D = words[3];

    const auto rn = _keyGen.roundCnt;

    B += _keyGen._S[0];
    D += _keyGen._S[1];

    for (int i = 1; i <= rn; ++i) {
      const auto u = _detailRC6::cycleLeft(D * (2 * D + 1), 5);
      const auto t = _detailRC6::cycleLeft(B * (2 * B + 1), 5);
      A = _detailRC6::cycleLeft(A ^ t, u) + _keyGen._S[2 * i];
      C = _detailRC6::cycleLeft(C ^ u, t) + _keyGen._S[2 * i + 1];
      std::tie(A, B, C, D) = std::tuple(B, C, D, A);
    }

    A += _keyGen._S[2 * rn + 2];
    C += _keyGen._S[2 * rn + 3];

    std::vector<std::byte> res(16);
    const std::array words2 = {A, B, C, D};
    if constexpr (std::endian::native == std::endian::big) {
      for (auto& w : words) w = std::byteswap(w);
    }
    std::memcpy(res.data(), words2.data(), res.size());

    return res;
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    if (in.size() != 16) {
      throw std::runtime_error("block must be 128bit");
    }
    std::array<std::byte, 16> raw_state;
    std::memcpy(raw_state.data(), in.data(), 16);

    auto words = std::bit_cast<std::array<uint32_t, 4>>(raw_state);

    if constexpr (std::endian::native == std::endian::big) {
      for (auto& w : words) w = std::byteswap(w);
    }

    uint32_t A = words[0];
    uint32_t B = words[1];
    uint32_t C = words[2];
    uint32_t D = words[3];

    const auto rn = _keyGen.roundCnt;

    C -= _keyGen._S[2 * rn + 3];
    A -= _keyGen._S[2 * rn + 2];

    for (int i = rn; i >= 1; --i) {
      std::tie(A, B, C, D) = std::tuple(D, A, B, C);
      const auto u = _detailRC6::cycleLeft(D * (2 * D + 1), 5);
      const auto t = _detailRC6::cycleLeft(B * (2 * B + 1), 5);
      C = _detailRC6::cycleRight(C - _keyGen._S[2 * i + 1], t) ^ u;
      A = _detailRC6::cycleRight(A - _keyGen._S[2 * i], u) ^ t;
    }

    D -= _keyGen._S[1];
    B -= _keyGen._S[0];

    std::vector<std::byte> res(16);
    const std::array words2 = {A, B, C, D};
    if constexpr (std::endian::native == std::endian::big) {
      for (auto& w : words) w = std::byteswap(w);
    }
    std::memcpy(res.data(), words2.data(), res.size());

    return res;
  }
};
}  // namespace meow::cypher::symm::RC6