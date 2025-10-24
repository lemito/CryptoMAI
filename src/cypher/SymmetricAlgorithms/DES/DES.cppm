/**
 * https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 */
module;

#include <unistd.h>

#include <bit>
#include <cassert>
#include <iomanip>
#include <ios>
#include <iostream>

#include "debug.h"

export module cypher.DES;

import <cstdint>;
import <array>;
import <cstddef>;
import <memory>;
import <span>;
import <stdexcept>;
import <tuple>;
import <vector>;

import cypher.FeistelNet;
import cypher.utils;
import cypher;
import cypher.DES.des_tables;

export class BadDESKey final : public std::exception {
 public:
  BadDESKey() {}
  explicit BadDESKey(const std::string&) {}
  const char* what() const noexcept override {
    return "Плохой ключ - нечетность всех 8 байт в каждом бите не выполнена";
  }
};

namespace meow::cypher::symm::_detailDES {
class DESGenRoundKey final : public IGenRoundKey {
  // 1100|1110 => 00|10 => 1|0 => 1 - нечетн
  // 1101|1110 => 00|11 => 1|1 => 0 - четн
  static bool isGoodByte(const std::vector<std::byte>& in) {
    for (const auto& elem : in) {
      const auto masked = elem & static_cast<std::byte>(0xFF);

      if (const uint8_t value = std::to_integer<uint8_t>(masked);
          (std::popcount(value) & 1) == 1) {
        return false;
      }
    }
    return true;
  }

 public:
  explicit DESGenRoundKey(const size_t RoundCnt) : IGenRoundKey(RoundCnt) {}
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] constexpr std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) const override {
    assert(roundCnt == 16);
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    if (inputKey.size() != 8) {
      throw std::runtime_error("ключ должен быть 8 байт == 64 бит");
    }
    // TODO: ТУТ НАДО ДОДЕЛАТЬ ПРОВЕРКУ КЛЮЧА
    if (I_WANT_CHECK_KEY && !isGoodByte(inputKey)) {
      throw BadDESKey();
    }

    std::vector res(roundCnt, std::vector<std::byte>());

    const auto pre = permutate::permutation(
        inputKey, PC1, permutate::bitIndexingRule::MSB2LSB, 1);

    // C-старшие 28 бит, D - младшие
    std::uint32_t C = 0, D = 0;

    for (size_t i = 0; i < 3; ++i) {
      C = C << 8 | std::to_integer<std::uint32_t>(pre[i]);
    }
    C = C << 4 | std::to_integer<std::uint32_t>(pre[3]) >> 4 & 0x0F;
    // C = (C << 4) | ((std::to_integer<std::uint32_t>(pre[3]) & 0xF0) >> 4);

    D = std::to_integer<std::uint32_t>(pre[3]) & 0x0F;
    for (size_t i = 4; i < 7; ++i) {
      D = D << 8 | std::to_integer<std::uint32_t>(pre[i]);
    }

    C &= 0x0FFFFFFF;
    D &= 0x0FFFFFFF;

    for (size_t i = 0; i < roundCnt; i++) {
      // C = ((C << SHIFTS[i]) | (C >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
      // D = ((D << SHIFTS[i]) | (D >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
      C = utils::ShiftBytesLeft(C, SHIFTS[i], 28);
      D = utils::ShiftBytesLeft(D, SHIFTS[i], 28);

      std::vector<std::byte> preBlock(
          7);  // обрезаем по 1 биту 8 раз - там они контрольные
      const std::uint64_t prepre = (static_cast<std::uint64_t>(C) << 28) | D;
      for (int j = 0; j < 7; j++) {
        preBlock[j] = static_cast<std::byte>((prepre >> ((6 - j) * 8)) & 0xFF);
      }

      res[i] = permutate::permutation(std::move(preBlock), PC2,
                                      permutate::bitIndexingRule::MSB2LSB, 1);

      // for (const auto& elem : res[i]) {
      //   std::cout << std::hex << std::setw(2) << std::setfill('0')
      //             << std::to_integer<int>(elem);
      // }
      // std::cout << std::endl;
    }

    return res;
  }
};

export class DESEncryptionDecryption final : public IEncryptionDecryption {
 public:
  /**
   * @brief
   * @param in
   * @return {строка, колонка}
   */
  static std::tuple<uint8_t, uint8_t> _findIxSBlock(const std::byte in) {
    const uint8_t row = (std::to_integer<uint8_t>(in) & 0b00100000) >> 4 |
                        std::to_integer<uint8_t>(in) & 0b00000001;

    const uint8_t column = (std::to_integer<uint8_t>(in) & 0b00011110) >> 1;

    return {row, column};
  }

  /**
   * @brief
   * @param RC
   * @param round
   * @return
   */
  static std::byte _findNewElem(const std::tuple<uint8_t, uint8_t>& RC,
                                const size_t round) {
    auto [row, column] = RC;
    return static_cast<std::byte>(S[round][row][column]);
  }

  /**
   * @brief
   * @param in
   * @return
   */
  static std::vector<std::byte> _doSBlock(const std::vector<std::byte>& in) {
    assert(in.size() == 6);

    std::vector res(4, std::byte{0});

    for (size_t i = 0; i < 8; i++) {
      const size_t biteIx = i * 6 / 8;
      const size_t bitIff = i * 6 % 8;

      uint8_t six_bits;
      if (bitIff <= 2) {
        six_bits =
            (static_cast<uint8_t>(in[biteIx]) >> (2 - bitIff)) & 0b00111111;
      } else {
        six_bits =
            ((static_cast<uint8_t>(in[biteIx]) << (bitIff - 2)) |
             (static_cast<uint8_t>(in[biteIx + 1]) >> ((8 + 2) - bitIff))) &
            0b00111111;
      }

      auto RC = _findIxSBlock(static_cast<std::byte>(six_bits));
      const auto s_val = static_cast<uint8_t>(_findNewElem(std::move(RC), i));

      const size_t resIx = i / 2;
      const size_t resShift = (i % 2 == 0) ? 4 : 0;
      res[resIx] |= static_cast<std::byte>(s_val << resShift);
    }

    return res;
  }

  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    auto big = permutate::permutation(inputBlock, E,
                                      permutate::bitIndexingRule::MSB2LSB, 1);

    if (big.size() != roundKey.size()) {
      throw std::runtime_error(
          "размер раундового ключа не совпал с размером расширенного блока "
          "(ожидается 6 байт / 48 бит)");
    }

    auto xored = xorSpan(std::move(big), roundKey);

    auto pre_res = _doSBlock(std::move(xored));

    return permutate::permutation(std::move(pre_res), P,
                                  permutate::bitIndexingRule::MSB2LSB, 1);
  }
};
}  // namespace meow::cypher::symm::_detailDES

export namespace meow::cypher::symm::DES {
class DES final : public FeistelNet::FeistelNet {
 public:
  // constexpr void setRoundKeys(
  //     const std::vector<std::byte>& encryptionKey) override {
  //   if (encryptionKey.empty()) {
  //     throw std::runtime_error("ключик пустой - это плохо");
  //   }
  //   if (encryptionKey.size() != 8) {
  //     throw std::runtime_error("ключик должен юыть 64 бит(или 8 байт)");
  //   }
  //   this->setRoundKeys(encryptionKey);
  //   _roundKeys = this->getRoundKeys();
  // }

  DES()
      : FeistelNet(std::make_shared<_detailDES::DESGenRoundKey>(16),
                   std::make_shared<_detailDES::DESEncryptionDecryption>()) {};

  // explicit DES(const std::span<std::byte> key)
  //     : FeistelNet(16, std::make_shared<_detailDES::DESGenRoundKey>(16),
  //                  std::make_shared<_detailDES::DESEncryptionDecryption>()) {
  //   std::vector<std::byte> k;
  //   k.assign(key.begin(), key.end());
  //   this->setRoundKeys(k);
  // }

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    auto pre =
        permutate::permutation(in, IP, permutate::bitIndexingRule::MSB2LSB, 1);
    auto encr = FeistelNet::encrypt(std::move(pre));
    return permutate::permutation(std::move(encr), IP_inv,
                                  permutate::bitIndexingRule::MSB2LSB, 1);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    auto pre =
        permutate::permutation(in, IP, permutate::bitIndexingRule::MSB2LSB, 1);
    auto decr = FeistelNet::decrypt(std::move(pre));
    return permutate::permutation(std::move(decr), IP_inv,
                                  permutate::bitIndexingRule::MSB2LSB, 1);
  }
};
}  // namespace meow::cypher::symm::DES