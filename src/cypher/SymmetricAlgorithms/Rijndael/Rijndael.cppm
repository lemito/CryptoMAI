/**
 * все тот же стандарт -
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */
module;
// #include <cstddef>
#include <any>
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
import <iostream>;
import <print>;

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
 public:
  // Number of columns (32-bit words) comprising the State
  size_t _Nb;
  // Number of 32-bit words comprising the Cipher Key
  size_t _Nk;  // 4 or 6 or 8
  // Number of rounds, which is a function of Nk and Nb (which is fixed).
  size_t _Nr;  // 10 or 12 or 14

  uint32_t _mod;

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

  // =================================================================

  // сдвиг строчки влево
  constexpr void shiftRows(std::span<std::byte> state) const {
    if (state.empty()) {
      throw std::runtime_error("shiftRows state empty :((");
    }
    if (state.size() != 4 * _Nb) {
      throw std::runtime_error("mixColumns: state size is too small");
    }

    const std::array shifts = {0, 1, (_Nb == 8) ? 3 : 2, (_Nb == 8) ? 4 : 3};

    const std::vector cpy(state.begin(), state.end());

    for (size_t r = 1; r < 4; r++) {
      for (size_t c = 0; c < _Nb; c++) {
        const size_t pos = (c + shifts[r]) % _Nb;
        state[r * _Nb + c] = cpy[r * _Nb + pos];
      }
    }
  }

  // а туточки вправо
  constexpr void inv_shiftRows(std::span<std::byte> state) const {
    if (state.empty()) {
      throw std::runtime_error("inv_shiftRows state empty :((");
    }
    if (state.size() != 4 * _Nb) {
      throw std::runtime_error("mixColumns: state size is too small");
    }
    const std::array shifts = {0, 1, (_Nb == 8) ? 3 : 2, (_Nb == 8) ? 4 : 3};
    const std::vector cpy(state.begin(), state.end());

    for (size_t r = 1; r < 4; r++) {
      for (size_t col = 0; col < _Nb; col++) {
        const size_t pos = (col - shifts[r] + _Nb) % _Nb;
        state[r * _Nb + col] = cpy[r * _Nb + pos];
      }
    }
  }

  constexpr void subBytes(std::span<std::byte> state) const {
    if (state.empty()) {
      throw std::runtime_error("subBytes state empty :((");
    }
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] = _S_box[static_cast<uint8_t>(state[i])];
    }
  }

  constexpr void inv_subBytes(std::span<std::byte> state) const {
    if (state.empty()) {
      throw std::runtime_error("inv_subBytes state empty :((");
    }
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] = _inv_S_box[static_cast<uint8_t>(state[i])];
    }
  }

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
    if (state.empty()) {
      throw std::runtime_error("mixColumns state empty :((");
    }
    if (state.size() != 4 * _Nb) {
      throw std::runtime_error("mixColumns: state size is too small");
    }

    const std::vector cpy(state.begin(), state.end());

    for (size_t c = 0; c < _Nb; ++c) {
      const std::byte s0 = cpy[0 * _Nb + c];
      const std::byte s1 = cpy[1 * _Nb + c];
      const std::byte s2 = cpy[2 * _Nb + c];
      const std::byte s3 = cpy[3 * _Nb + c];

      state[0 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod)) ^
          s2 ^ s3;

      state[1 * _Nb + c] =
          s0 ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod)) ^
          s3;

      state[2 * _Nb + c] =
          s0 ^ s1 ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod));

      state[3 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x03),
                                      static_cast<std::byte>(_mod)) ^
          s1 ^ s2 ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x02),
                                      static_cast<std::byte>(_mod));
    }
  }

  /*
   *  a^-1(x) = 0x0bx^3 + 0x0dx^2 + 0x09x + 0x0e
   *  или матрица
   *
   */
  constexpr void inv_mixColumns(std::span<std::byte> state) const {
    if (state.empty()) {
      throw std::runtime_error("inv_mixColumns state empty :((");
    }
    const std::vector cpy(state.begin(), state.end());

    for (size_t c = 0; c < _Nb; ++c) {
      const std::byte s0 = cpy[0 * _Nb + c];
      const std::byte s1 = cpy[1 * _Nb + c];
      const std::byte s2 = cpy[2 * _Nb + c];
      const std::byte s3 = cpy[3 * _Nb + c];

      state[0 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod));

      state[1 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod));

      state[2 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod));

      state[3 * _Nb + c] =
          math::GaloisFieldPoly::mult(s0, static_cast<std::byte>(0x0b),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s1, static_cast<std::byte>(0x0d),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s2, static_cast<std::byte>(0x09),
                                      static_cast<std::byte>(_mod)) ^
          math::GaloisFieldPoly::mult(s3, static_cast<std::byte>(0x0e),
                                      static_cast<std::byte>(_mod));
    }
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

  static auto inv_affine(const std::byte inv) -> std::byte {
    const uint8_t x = std::to_integer<uint8_t>(inv);

    const uint8_t shift1 = x << 1 | x >> 7;
    const uint8_t shift2 = x << 3 | x >> 5;
    const uint8_t shift3 = x << 6 | x >> 2;

    return static_cast<std::byte>(shift1 ^ shift2 ^ shift3);
  }

  // [[nodiscard]] static constexpr std::vector<std::byte> rotWord(
  //     std::vector<std::byte> word) {
  //   if (word.size() != 4) {
  //     throw std::invalid_argument("word must be 4 bytes len");
  //   }
  //   // return std::vector{word[1], word[2], word[3], word[0]};
  //   std::rotate(word.begin(), word.begin() + 1, word.end());
  //   return word;
  // }

  // [[nodiscard]] constexpr std::vector<std::byte> subWord(
  //     const std::vector<std::byte>& word) const {
  //   std::vector<std::byte> result(4);
  //   for (size_t i = 0; i < 4; ++i) {
  //     result[i] = _S_box[static_cast<uint8_t>(word[i])];
  //   }
  //   return result;
  // }

  static constexpr void rotWord(std::vector<std::byte>& word) {
    if (word.size() != 4) {
      throw std::invalid_argument("word must be 4 bytes len");
    }
    std::ranges::rotate(word, word.begin() + 1);
  }

  constexpr void subWord(std::vector<std::byte>& word) const {
    for (size_t i = 0; i < 4; ++i) {
      word[i] = _S_box[static_cast<uint8_t>(word[i])];
    }
  }

  auto genSBox() -> void {
    // афинное преобразование : обратный байт * матрицу специальную XOR 0x63
    // умножение есть & а потом всебайтовый xor
    for (size_t i = 0; i < SBOX_SIZ; ++i) {
      const auto inv = math::GaloisFieldPoly::invElem(
          static_cast<std::byte>(i), static_cast<std::byte>(_mod));
      _S_box[i] = static_cast<std::byte>(
          std::to_integer<std::uint8_t>(affine(inv)) ^ 0x63);

      const auto affine_result = inv_affine(static_cast<std::byte>(i));
      _inv_S_box[i] = math::GaloisFieldPoly::invElem(
          static_cast<std::byte>(std::to_integer<std::uint8_t>(affine_result) ^
                                 0x05),
          static_cast<std::byte>(_mod));
    }
  }

  template <size_t N>
  [[nodiscard]] constexpr auto genRcon() const
      -> std::vector<std::vector<std::byte>> {
    // rcon тупо из стандарта - 1 байт меняются, а остальные 3 нули
    static_assert(N == 10UL || N == 12UL || N == 14UL, "N must be 10, 8, or 7");

    std::vector _rcon(N, std::vector<std::byte>(4));
    _rcon.shrink_to_fit();

    auto rc = std::byte{0x01};

    for (size_t i = 0; i < N; i++) {
      _rcon[i][0] = std::byte{rc};
      _rcon[i][1] = std::byte{0x00};
      _rcon[i][2] = std::byte{0x00};
      _rcon[i][3] = std::byte{0x00};

      rc = math::GaloisFieldPoly::multToX(std::byte{rc},
                                          static_cast<std::byte>(_mod));
    }

    return _rcon;
  }

  [[nodiscard]] constexpr auto pickRcon() const -> auto {
    switch (_Nk) {
      case 4:
        return genRcon<10>();
      case 6:
        return genRcon<12>();
      case 8:
        return genRcon<14>();
      default:
        throw std::runtime_error("rcon gen err");
    }
  }

  auto getRcon() const { return pickRcon(); }

  [[nodiscard]] constexpr auto keyGen(const std::span<std::byte> key) const
      -> std::vector<std::vector<std::byte>> {
    if (key.size() != 4 * _Nk) {
      throw std::runtime_error("keyGen: bad key size " +
                               std::to_string(key.size()) + ", expected " +
                               std::to_string(4 * _Nk));
    }

    const auto _rcon = getRcon();

    // std::vector rk(_Nb * (_Nr + 1), std::vector<std::byte>(4));
    std::vector<std::vector<std::byte>> rk;
    rk.resize(_Nb * (_Nr + 1));
    rk.shrink_to_fit();
    for (auto& elem : rk) {
      elem.resize(4);
      elem.shrink_to_fit();
    }

    for (size_t i = 0; i < _Nk; ++i) {
      rk[i] = {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
    }

    for (size_t i = _Nk; i < _Nb * (_Nr + 1); ++i) {
      std::vector<std::byte> tmp = rk[i - 1];

      if (i % _Nk == 0) {
        // tmp = subWord(rotWord(tmp));
        rotWord(tmp);
        subWord(tmp);

        const size_t rcon_idx = (i / _Nk) - 1;
        if (rcon_idx >= _rcon.size()) {
          throw std::runtime_error("keyGen: Rcon index out of bounds " +
                                   std::to_string(rcon_idx) + " vs " +
                                   std::to_string(_rcon.size()));
        }

        tmp[0] = tmp[0] ^ _rcon[rcon_idx][0];
      } else if (_Nk > 6 && i % _Nk == 4) {
        // tmp = subWord(tmp);
        subWord(tmp);
      }

      for (size_t j = 0; j < 4; ++j) {
        if (i - _Nk >= rk.size()) {
          throw std::runtime_error("keyGen: rk index out of bounds");
        }
        rk[i][j] = rk[i - _Nk][j] ^ tmp[j];
      }
    }

    std::vector res(_Nr + 1, std::vector<std::byte>(_Nb * 4));
    for (size_t round = 0; round <= _Nr; ++round) {
      for (size_t column = 0; column < _Nb; ++column) {
        std::ranges::copy(rk[round * _Nb + column],
                          res[round].begin() + column * 4);
      }
    }

    return res;
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
    _blockSize = _Nb * 4;
    _Nk = key_size / (8 * 4);

    // тут наверное сэйм хардкод, но тут я перешел в байты и раздача раундов
    /*
     * 10 12  14
     * 12 12  14
     * 14 14  14
     */
    switch (_Nk) {
      case 4: {
        // genRcon<10>();
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
        // genRcon<8>();
        switch (_Nb) {
          case 4:
            _Nr = 12;
            break;
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
        // genRcon<7>();
        switch (_Nb) {
          case 4:
            _Nr = 14;
            break;
          case 6:
            _Nr = 14;
            break;
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

  static void AddRoundKey(std::vector<std::byte>& state,
                          const std::vector<std::byte>& rK) {
    if (state.empty()) {
      throw std::runtime_error("EncRound state empty");
    }
    if (rK.empty()) {
      throw std::runtime_error("EncRound rK empty");
    }
    if (state.size() != rK.size()) {
      throw std::runtime_error("state len != rK len");
    }
    for (size_t i = 0; i < state.size(); ++i) {
      state[i] ^= rK[i];
    }
  }

  void EncRound(std::vector<std::byte>& state,
                const std::vector<std::byte>& rK) const {
    if (state.empty()) {
      throw std::runtime_error("EncRound state empty");
    }
    if (rK.empty()) {
      throw std::runtime_error("EncRound rK empty");
    }
    if (rK.size() != 4 * _Nb) {
      throw std::runtime_error("rK badd size");
    }
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    AddRoundKey(state, rK);
  }

  void DecRound(std::vector<std::byte>& state,
                const std::vector<std::byte>& rK) const {
    if (state.empty()) {
      throw std::runtime_error("DecRound state empty");
    }
    if (rK.empty()) {
      throw std::runtime_error("DecRound rK empty");
    }
    if (rK.size() != 4 * _Nb) {
      throw std::runtime_error("rK badd size");
    }
    inv_shiftRows(state);
    inv_subBytes(state);
    AddRoundKey(state, rK);
    inv_mixColumns(state);
  }

  void FinalRound(std::vector<std::byte>& state,
                  const std::vector<std::byte>& rK) const {
    if (state.empty()) {
      throw std::runtime_error("FinalRound state empty");
    }
    if (rK.empty()) {
      throw std::runtime_error("FinalRound rK empty");
    }
    if (rK.size() != 4 * _Nb) {
      throw std::runtime_error("rK badd size");
    }
    if (rK.begin() != _roundKeys[_Nr].begin()) {
      throw std::runtime_error("bad rK for DecFinalRound");
    }
    subBytes(state);
    shiftRows(state);
    AddRoundKey(state, rK);
  }

  void DecFinalRound(std::vector<std::byte>& state,
                     const std::vector<std::byte>& rK) const {
    if (state.empty()) {
      throw std::runtime_error("DecFinalRound state empty");
    }
    if (rK.empty()) {
      throw std::runtime_error("DecFinalRound rK empty");
    }
    if (rK.size() != 4 * _Nb) {
      throw std::runtime_error("rK badd size");
    }
    if (rK.begin() != _roundKeys[0].begin()) {
      throw std::runtime_error("bad rK for DecFinalRound");
    }
    inv_shiftRows(state);
    inv_subBytes(state);
    AddRoundKey(state, rK);
  }

  [[nodiscard("")]] constexpr std ::vector<std ::vector<std ::byte>>
  genRoundKeys(const std ::vector<std ::byte>& inputKey) override {
    return keyGen(const_cast<std::vector<std ::byte>&>(inputKey));
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
    this->_roundKeys = genRoundKeys(encryptionKey);
    if (this->_roundKeys.empty()) {
      throw std::runtime_error("setRoundKeys: failed to generate round keys");
    }
    if (this->_roundKeys.size() != (_Nr + 1)) {
      throw std::runtime_error("setRoundKeys: wrong number of round keys " +
                               std::to_string(this->_roundKeys.size()) +
                               " but need " + std::to_string(_Nr + 1));
    }
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encrypt(
      const std::vector<std ::byte>& in) const override {
    if (_roundKeys.empty()) {
      throw std::runtime_error("Rijndael - empty _roundKeys");
    }
    if (in.size() != _Nb * 4) {
      std::cout << _Nb << " " << _Nb * 4 << " " << in.size() << std::endl;
      throw std::runtime_error("enc: in size isnt eq _Nb");
    }
    std::vector copy = in;
    AddRoundKey(copy, (_roundKeys[0]));
    for (size_t i = 1; i < _Nr; ++i) {
      EncRound(copy, (_roundKeys[i]));
    }
    FinalRound(copy, (_roundKeys[_Nr]));
    return copy;
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> decrypt(
      const std ::vector<std ::byte>& in) const override {
    if (_roundKeys.empty()) {
      throw std::runtime_error("Rijndael - empty _roundKeys");
    }
    if (in.size() != _Nb * 4) {
      std::cout << _Nb << " " << _Nb * 4 << " " << in.size() << std::endl;
      throw std::runtime_error("dec: in size isnt eq _Nb ");
    }
    std::vector copy = in;
    AddRoundKey(copy, (_roundKeys[_Nr]));
    for (int i = static_cast<int>(_Nr) - 1; i > 0; --i) {
      DecRound(copy, (_roundKeys[i]));
    }
    DecFinalRound(copy, (_roundKeys[0]));
    return copy;
  }
};

}  // namespace meow::cypher::symm::Rijndael
