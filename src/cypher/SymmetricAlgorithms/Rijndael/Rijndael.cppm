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
import math.GaloisFieldPoly;
import cypher.utils;
import <array>;
import <span>;
import <cstdint>;
import <vector>;

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

  uint32_t _mod;

 public:
#define RCON_MAX_SIZ (10)

  std::vector<uint32_t> _rcon{};

#define SBOX_SIZ (1 << 8)

  // таблицы 16x16 => i == 16 * row + column
  std::array<std::byte, SBOX_SIZ> _S_box;
  std::array<std::byte, SBOX_SIZ> _inv_S_box;

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

  static auto rotWord(std::span<std::byte> state) -> void {
    if (state.size() != 4) {
      throw std::invalid_argument("word must be 4 bytes len");
    }
    // тут берем 4 байта (это слово) и возвращаем новые 4, после подстановки в
    const auto pI = reinterpret_cast<uint32_t*>(state.data());
    *pI = (*pI << 1) | (*pI >> (32 - 1));
  }

  constexpr void shiftRows(std::span<std::byte> state) {}

  constexpr void inv_shiftRows(std::span<std::byte> state) {}

  constexpr void subBytes(std::span<std::byte> state) {}

  constexpr void inv_subBytes(std::span<std::byte> state) {}

  [[nodiscard]] constexpr auto subWord(const int32_t in) const -> uint32_t {
    // тут берем 4 байта (это слово) и возвращаем новые 4, после подстановки в
    // S_box
    uint32_t res = 0;

    res |= static_cast<uint32_t>(this->_S_box[in >> 32 - 8 & 0xFF] << 32 - 8);
    res |= static_cast<uint32_t>(_S_box[in >> 32 - 16 & 0xFF] << 32 - 16);
    res |= static_cast<uint32_t>(_S_box[in >> (32 - 24) & 0xFF] << (32 - 24));
    res |= static_cast<uint32_t>(_S_box[in & 0xFF]);

    return res;
  }

  constexpr void mixColumns(std::span<std::byte> state) {}

  constexpr void inv_mixColumns(std::span<std::byte> state) {}

 public:
  static auto affine(const std::byte inv) -> std::byte {
    // умножение есть & а потом всебайтовый xor
    // 5 xor, так как единиц в волшебной матрице тоже 5 и на все остальные всё
    // равно
    const uint8_t x = std::to_integer<uint8_t>(inv);

    const uint8_t shift1 = (x << 1) | (x >> 7);
    const uint8_t shift2 = (x << 2) | (x >> 6);
    const uint8_t shift3 = (x << 3) | (x >> 5);
    const uint8_t shift4 = (x << 4) | (x >> 4);

    return static_cast<std::byte>(x ^ shift1 ^ shift2 ^ shift3 ^ shift4);
  }

  auto genSBox() -> void {
    // афинное преобразование : обратный байт * матрицу специальную XOR 0x63
    // умножение есть & а потом всебайтовый xor
    for (size_t i = 0; i < SBOX_SIZ; ++i) {
      const auto inv = math::GaloisFieldPoly::invElem(
          static_cast<std::byte>(i), static_cast<std::byte>(_mod));
      const std::byte meow = affine(inv);
      const auto newVal =
          static_cast<std::byte>(std::to_integer<std::uint8_t>(meow) ^ 0x63);
      _S_box[i] = newVal;
      _inv_S_box[std::to_integer<int>(newVal)] = static_cast<std::byte>(i);
    }
  }

  template <size_t N>
  constexpr void genRcon() {
    // rcon тупо из стандарта - 1 байт меняются, а остальные 3 нули
    static_assert(N == 10UL || N == 8UL || N == 7UL, "N must be 10, 8, or 7");
    _rcon.resize(N);
    uint32_t rc = 0x01;

    for (size_t i = 0; i < N; i++) {
      _rcon[i] = rc << 24;

      rc <<= 1;
      if (rc & 0x100) {
        rc ^= _mod;
      }
      rc &= 0xFF;
    }
  }

 public:
  Rijndael(const size_t block_size, const size_t key_size, const uint32_t mod)
      : IGenRoundKey(0), _mod(mod), _S_box(), _inv_S_box() {
    if (block_size != 128 && block_size != 192 && block_size != 256) {
      throw std::invalid_argument("Block_Size only 128/192/256 bit");
    }
    if (key_size != 128 && key_size != 192 && key_size != 256) {
      throw std::invalid_argument("key_size only 128/192/256 bit");
    }

    _Nb = block_size / (8 * 4);
    _Nk = key_size / (8 * 4);

    // тут наверное сэйм хардкод, но тут я перешел в байты и раздача раундов
    /*
     * 10 12  14
     * 12 12  14
     * 14 14  14
     */
    switch (_Nk) {
      case 4: {
        genRcon<10>();
        switch (_Nb) {
          case 4: {
            _Nr = 10;
          } break;
          case 6: {
            _Nr = 12;
          } break;
          case 8: {
            _Nr = 14;
          } break;
          default:
            throw std::runtime_error("_Nb err");
        }
      } break;
      case 6: {
        genRcon<8>();
        switch (_Nb) {
          case 4: {
            _Nr = 12;
          } break;
          case 6: {
            _Nr = 12;
          } break;
          case 8: {
            _Nr = 14;
          } break;
          default:
            throw std::runtime_error("_Nb err");
        }
      } break;
      case 8: {
        genRcon<7>();
        switch (_Nb) {
          case 4: {
            _Nr = 14;
          } break;
          case 6: {
            _Nr = 14;
          } break;
          case 8: {
            _Nr = 14;
          } break;
          default:
            throw std::runtime_error("_Nb err");
        }
      } break;
      default:
        throw std::runtime_error("_Nk err");
    }

    genSBox();
  }

  static void AddRoundKey(std::span<std::byte> state,
                          const std::span<std::byte> rK) {
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] = state[i] ^ rK[i];
    }
  }

  void EncRound(std::span<std::byte> state, std::span<std::byte> rK) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    AddRoundKey(state, rK);
  }

  void DecRound(std::span<std::byte> state, std::span<std::byte> rK) {
    AddRoundKey(state, rK);
    inv_mixColumns(state);
    inv_shiftRows(state);
    subBytes(state);
  }

  void FinalRound(std::span<std::byte> state, std::span<std::byte> rK) {
    subBytes(state);
    shiftRows(state);
    AddRoundKey(state, rK);
  }

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