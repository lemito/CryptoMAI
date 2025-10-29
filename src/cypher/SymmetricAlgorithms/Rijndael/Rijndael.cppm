/**
 * все тот же стандарт -
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */
module;
#include <cstddef>
#include <vector>
export module Rijndael;
import cypher;
import <array>;
import <span>;
import <cstdint>;

export namespace meow::cypher::symm::Rijndael {
class Rijndael final : public IGenRoundKey,
                       IEncryptionDecryption,
                       ISymmetricCypher {
  /**
  state - это массив массивов байт 4x4
  но байты идут вниз
  0  4  8  12
  1  5  9  13
  2  6 10  14
  3  7 11  15
  */

  // Number of columns (32-bit words) comprising the State
  size_t _Nb = 4;
  // Number of 32-bit words comprising the Cipher Key
  size_t _Nk = 4;  // or 6 or 8
  // Number of rounds, which is a function of Nk and Nb (which is fixed).
  size_t _Nr = 10;  // or 12 or 14

  std::array<std::byte, 10> _rcon;

  // таблицы 16x16 => i == 16 * row + column
  std::array<std::byte, 256> _S_box;
  std::array<std::byte, 256> _inv_S_box;

  [[nodiscard]] constexpr auto getElemFromS(const size_t row,
                                            const size_t column) -> std::byte& {
    if (row >= 16) {
      throw std::runtime_error("row cant be >= 16");
    }
    if (column >= 16) {
      throw std::runtime_error("column cant be >= 16");
    }
    return _S_box[16 * row + column];
  }

  [[nodiscard]] constexpr auto getElemFromIS(const size_t row,
                                             const size_t column)
      -> std::byte& {
    if (row >= 16) {
      throw std::runtime_error("row cant be >= 16");
    }
    if (column >= 16) {
      throw std::runtime_error("column cant be >= 16");
    }
    return _inv_S_box[16 * row + column];
  }

  [[nodiscard]] constexpr auto getElemFromS(const size_t row,
                                            const size_t column) const
      -> const std::byte& {
    if (row >= 16) {
      throw std::runtime_error("row cant be >= 16");
    }
    if (column >= 16) {
      throw std::runtime_error("column cant be >= 16");
    }
    return _S_box[16 * row + column];
  }

  [[nodiscard]] constexpr auto getElemFromIS(const size_t row,
                                             const size_t column) const
      -> const std::byte& {
    if (row >= 16) {
      throw std::runtime_error("row cant be >= 16");
    }
    if (column >= 16) {
      throw std::runtime_error("column cant be >= 16");
    }
    return _inv_S_box[16 * row + column];
  }

  // TODO" вот это вот всё туду

  constexpr void rotWord(std::span<std::byte> state) {}

  constexpr void shiftRows(std::span<std::byte> state) {}

  constexpr void inv_shiftRows(std::span<std::byte> state) {}

  constexpr void subBytes(std::span<std::byte> state) {}

  constexpr void inv_subBytes(std::span<std::byte> state) {}

  [[nodiscard]] constexpr auto subWord(const uint32_t word) const -> uint32_t {
    // тут берем 4 байта (это слово) и возвращаем новые 4, после подстановки в
    // S_box
    uint32_t res = 0;

    res |= static_cast<uint32_t>(this->_S_box[(word >> (32 - 8)) & 0xFF]
                                 << (32 - 8));
    res |=
        static_cast<uint32_t>(_S_box[(word >> (32 - 16)) & 0xFF] << (32 - 16));
    res |=
        static_cast<uint32_t>(_S_box[(word >> (32 - 24)) & 0xFF] << (32 - 24));
    res |= static_cast<uint32_t>(_S_box[(word) & 0xFF]);

    return res;
  }

  constexpr void mixColumns(std::span<std::byte> state) {}

  constexpr void inv_mixColumns(std::span<std::byte> state) {}

 public:
  Rijndael() : IGenRoundKey(0) {}
  [[nodiscard("")]] constexpr std ::vector<std ::vector<std ::byte>>
  genRoundKeys(const std ::vector<std ::byte>& inputKey) const override {
    // TODO: Implement this pure virtual method.
    // static_assert(false, "Method `genRoundKeys` is not implemented.");
    return {{}};
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encryptDecryptBlock(
      const std ::vector<std ::byte>& inputBlock,
      const std ::vector<std ::byte>& roundKey) const override {
    // TODO: Implement this pure virtual method.
    // static_assert(false, "Method `encryptDecryptBlock` is not implemented.")
    return {};
  }

  constexpr void setRoundKeys(
      const std ::vector<std ::byte>& encryptionKey) override {
    // TODO: Implement this pure virtual method.
    // static_assert(false, "Method `setRoundKeys` is not implemented.");
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encrypt(
      const std ::vector<std ::byte>& in) const override {
    // TODO: Implement this pure virtual method.
    // static_assert(false, "Method `encrypt` is not implemented.");
    return {};
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> decrypt(
      const std ::vector<std ::byte>& in) const override {
    // TODO: Implement this pure virtual method.
    // static_assert(false, "Method `decrypt` is not implemented.");
    return {};
  }
};

}  // namespace meow::cypher::symm::Rijndael