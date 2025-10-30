/**
 * все тот же стандарт -
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */
module;
// #include <cstddef>
#include <vector>

#include "debug.h"
export module Rijndael;
import cypher;
import math.GaloisFieldPoly;
import cypher.utils;
import <array>;
import <algorithm>;
import <cstring>;
import <span>;
import <cstdint>;
import <vector>;

export namespace meow::cypher::symm::Rijndael {
class Rijndael final : public ISymmetricCypher,
                       IGenRoundKey,
                       IEncryptionDecryption {
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

  std::size_t _blockSize;  // размер блока указан в байт (для DES = 8)

 public:
  // std::vector<uint32_t> _round_keys;

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

  // сдвиг строчки влево
  constexpr void shiftRows(std::span<std::byte> state) const {
    const auto copy = state;
    for (size_t r = 1; r < 4; ++r) {
      for (size_t c = 0; c < _Nb; ++c) {
        const size_t pos = (c - r + _Nb) % _Nb;
        state[r + 4 * pos] = copy[r + 4 * c];
      }
    }
  }

  // а туточки вправо
  constexpr void inv_shiftRows(std::span<std::byte> state) const {
    const auto copy = state;
    for (size_t r = 1; r < 4; ++r) {
      for (size_t c = 0; c < _Nb; ++c) {
        const size_t pos = (c + r) % _Nb;
        state[r + 4 * pos] = copy[r + 4 * c];
      }
    }
  }

  constexpr void subBytes(std::span<std::byte> state) const {
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] = _S_box[static_cast<uint8_t>(state[i])];
    }
  }

  constexpr void inv_subBytes(std::span<std::byte> state) const {
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] = _inv_S_box[static_cast<uint8_t>(state[i])];
    }
  }

  // [[nodiscard]] constexpr auto subWord(const uint32_t in) const -> uint32_t {
  //   // тут берем 4 байта (это слово) и возвращаем новые 4, после подстановки
  //   в
  //   // S_box
  //   uint32_t res = 0;
  //
  //   res |= static_cast<uint32_t>(_S_box[in >> 24 & 0xFF]) << 24;
  //   res |= static_cast<uint32_t>(_S_box[in >> 16 & 0xFF]) << 16;
  //   res |= static_cast<uint32_t>(_S_box[in >> 8 & 0xFF]) << 8;
  //   res |= static_cast<uint32_t>(_S_box[in & 0xFF]);
  //
  //   return res;
  // }

  constexpr auto subWord(std::span<std::byte> in) const -> void {
    if (in.size() != 4) {
      throw std::invalid_argument("word must be 4 bytes len");
    }
    for (size_t i = 0; i < in.size(); ++i) {
      in[i] = _S_box[std::to_integer<uint16_t>(in[i])];
    }
  }

  /*  тут происходит преобразование колонки: s` = s * a(x); s и s` - колонки
   *  a(x) = 0x03x^2 + 0x01x^2 + 0x01 x + 0x02
   *  s`0	 	02	03	01	01	s0
   *  s`1	        01	02	03	01	s1
   *  s`2	   =    01	01	02	03	s2
   * s`3	        03	01	01	02	s3
   *  поэтому тут нужно GF то самое волшебное -- сами эти полиномы являются
   * полиномами GF
   *
   * или матричное умножение
   */
  constexpr void mixColumns(std::span<std::byte> state) const {
    auto copy = state;
    for (size_t c = 0; c < _Nb; ++c) {
      const size_t off = 4 * c;

      copy[off] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 1],
                                      static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod)) ^
          state[off + 2] ^ state[off + 3];
      copy[off + 1] = state[off] ^
                      math::GaloisFieldPoly::mult(
                          state[off + 1], static_cast<std::byte>(0x02),
                          static_cast<std::byte>(_mod)) ^
                      math::GaloisFieldPoly::mult(
                          state[off + 2], static_cast<std::byte>(0x03),
                          static_cast<std::byte>(_mod)) ^
                      state[off + 3];
      copy[off + 2] = state[off] ^ state[off + 1] ^
                      math::GaloisFieldPoly::mult(
                          state[off + 2], static_cast<std::byte>(0x02),
                          static_cast<std::byte>(_mod)) ^
                      math::GaloisFieldPoly::mult(state[off + 3],
                                                  static_cast<std::byte>(0x03),
                                                  static_cast<std::byte>(_mod));
      copy[off + 3] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod)) ^
          state[off + 1] ^ state[off + 2] ^
          math::GaloisFieldPoly::mult(state[off + 3],
                                      static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod));
    }
    std::ranges::copy(copy, state.begin());
  }

  /*
   *  a^-1(x) = 0x0bx^3 + 0x0dx^2 + 0x09x + 0x0e
   *  или матрица
  *
   */
  constexpr void inv_mixColumns(std::span<std::byte> state) const {
    auto copy = state;
    for (size_t c = 0; c < _Nb; ++c) {
      const size_t off = 4 * c;

      copy[off] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 1],
                                      static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 2],
                                      static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 3],
                                      static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod));
      copy[off + 1] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 1],
                                      static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 2],
                                      static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod));
      copy[off + 2] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 1],
                                      static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 2],
                                      static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 3],
                                      static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod));
      copy[off + 3] =
          math::GaloisFieldPoly::mult(state[off], static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 1],
                                      static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 2],
                                      static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(state[off + 3],
                                      static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod));
    }
    std::ranges::copy(copy, state.begin());
  }

 public:
  static auto affine(const std::byte inv) -> std::byte {
    // умножение есть & а потом всебайтовый xor
    // 5 xor, так как единиц в волшебной матрице тоже 5 и на все остальные всё
    // равно
    const uint8_t x = std::to_integer<uint8_t>(inv);

    const uint8_t shift1 = x << 1 | x >> 7;
    const uint8_t shift2 = x << 2 | x >> 6;
    const uint8_t shift3 = x << 3 | x >> 5;
    const uint8_t shift4 = x << 4 | x >> 4;

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

  [[nodiscard]] static constexpr std::vector<std::byte> rotWord(
      const std::vector<std::byte>& word) {
    if (word.size() != 4) {
      throw std::invalid_argument("word must be 4 bytes len");
    }
    return std::vector{word[1], word[2], word[3], word[0]};
  }

  [[nodiscard]] constexpr std::vector<std::byte> subWord(
      const std::vector<std::byte>& word) const {
    std::vector<std::byte> result(4);
    for (size_t i = 0; i < 4; ++i) {
      result[i] = _S_box[static_cast<uint8_t>(word[i])];
    }
    return result;
  }

  void keyGen(const std::span<std::byte> key) {
    if (key.size() != 4 * _Nk) {
      throw std::runtime_error("bad key size");
    }

    _roundKeys.resize(_Nb * (_Nr + 1));
    for (auto& elem : _roundKeys) {
      elem.resize(4);
    }

    for (size_t i = 0; i < _Nk; ++i) {
      _roundKeys[i] = std::vector{key[4 * i], key[4 * i + 1], key[4 * i + 2],
                                  key[4 * i + 3]};
    }

    for (size_t i = _Nk; i < _Nb * (_Nr + 1); ++i) {
      std::vector<std::byte> temp = _roundKeys[i - 1];

      if (i % _Nk == 0) {
        temp = subWord(rotWord(temp));
        const uint32_t rcon_val = _rcon[i / _Nk - 1];
        const auto rcon_byte = static_cast<std::byte>((rcon_val >> 24) & 0xFF);
        temp[0] = temp[0] ^ rcon_byte;
      } else if (_Nk > 6 && i % _Nk == 4) {
        temp = subWord(temp);
      }

      for (size_t j = 0; j < 4; ++j) {
        _roundKeys[i][j] = _roundKeys[i - _Nk][j] ^ temp[j];
      }
    }

    auto getWord = [](const std::vector<std::byte>& word) -> uint32_t {
      return (static_cast<uint32_t>(static_cast<uint8_t>(word[0])) << 24) |
             (static_cast<uint32_t>(static_cast<uint8_t>(word[1])) << 16) |
             (static_cast<uint32_t>(static_cast<uint8_t>(word[2])) << 8) |
             (static_cast<uint32_t>(static_cast<uint8_t>(word[3])));
    };

    if (I_WANT_CHECK_KEY && _Nk == 4) {
      if (getWord(_roundKeys[4]) != 0xa0fafe17) {
        throw std::runtime_error("keygen err at round 4");
      }

      if (getWord(_roundKeys[10]) != 0x5935807a) {
        throw std::runtime_error("keygen err at round 10");
      }

      if (getWord(_roundKeys[7]) != 0x2a6c7605) {
        throw std::runtime_error("keygen err at round 7");
      }
    }
  }

 public:
  Rijndael(const size_t block_size, const size_t key_size, const uint32_t mod)
      : IGenRoundKey(0),
        _mod(mod),
        _blockSize(block_size),
        _S_box(),
        _inv_S_box() {
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
          case 4:
          case 6:
            _Nr = 12;
            break;
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
          case 4:
          case 6:
          case 8:
            _Nr = 14;
            break;
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

  void EncRound(std::span<std::byte> state, std::span<std::byte> rK) const {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    AddRoundKey(state, rK);
  }

  void DecRound(std::span<std::byte> state, std::span<std::byte> rK) const {
    inv_shiftRows(state);
    inv_subBytes(state);
    AddRoundKey(state, rK);
    inv_mixColumns(state);
  }

  void FinalRound(std::span<std::byte> state, std::span<std::byte> rK) const {
    subBytes(state);
    shiftRows(state);
    AddRoundKey(state, rK);
  }

  void DecFinalRound(std::span<std::byte> state,
                     std::span<std::byte> rK) const {
    inv_shiftRows(state);
    inv_subBytes(state);
    AddRoundKey(state, rK);
  }

  [[nodiscard("")]] constexpr std ::vector<std ::vector<std ::byte>>
  genRoundKeys(const std ::vector<std ::byte>& inputKey) override {
    keyGen(const_cast<std::vector<std ::byte>&>(inputKey));
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encryptDecryptBlock(
      const std ::vector<std ::byte>& inputBlock,
      const std ::vector<std ::byte>& roundKey) const override {
    // ЭТОТ МЕТОД ПРЕДПОЛАГАЛСЯ ТОЛЬКО ДЛЯ ФЕЙСТЕЛЯ КАК ФУНКЦИЯ ФЕЙСТЕЛЯ; ДЛЯ
    // SP-PERM ЭТО ПРОСТО ЗАГЛУШКА
    return {};
  }

  constexpr void setRoundKeys(
      const std ::vector<std ::byte>& encryptionKey) override {
    keyGen(const_cast<std::vector<std ::byte>&>(encryptionKey));
    _roundKeys = genRoundKeys(encryptionKey);
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encrypt(
      const std::vector<std ::byte>& in) const override {
    if (_roundKeys.empty()) {
      throw std::runtime_error("Rijndael - empty _roundKeys");
    }
    if (in.size() != _Nb) {
      throw std::runtime_error("in size isnt eq _Nb");
    }
    std::vector copy = in;
    AddRoundKey(std::span(copy),
                std::span(const_cast<std::vector<std::byte>&>(_roundKeys[0])));
    for (size_t i = 1; i < _Nr; ++i) {
      EncRound(std::span(copy),
               std::span(const_cast<std::vector<std::byte>&>(_roundKeys[i])));
    }
    FinalRound(std::span(copy),
               std::span(const_cast<std::vector<std::byte>&>(_roundKeys[_Nr])));
    return copy;
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> decrypt(
      const std ::vector<std ::byte>& in) const override {
    if (_roundKeys.empty()) {
      throw std::runtime_error("Rijndael - empty _roundKeys");
    }
    if (in.size() != _Nb) {
      throw std::runtime_error("in size isnt eq _Nb");
    }
    std::vector copy = in;
    AddRoundKey(
        std::span(copy),
        std::span(const_cast<std::vector<std::byte>&>(_roundKeys[_Nr])));
    for (int i = _Nr - 1; i > 0; --i) {
      DecRound(std::span(copy),
               std::span(const_cast<std::vector<std::byte>&>(_roundKeys[i])));
    }
    DecFinalRound(
        std::span(copy),
        std::span(const_cast<std::vector<std::byte>&>(_roundKeys[0])));
    return copy;
  }
};

}  // namespace meow::cypher::symm::Rijndael