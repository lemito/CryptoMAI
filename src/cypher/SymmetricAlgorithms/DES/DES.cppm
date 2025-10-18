/**
 * https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 */
module;

#include <memory>
#include <vector>

export module DES;

import cypher.FeistelNet;
import cypher.utils;
import cypher;
import cypher.DES.des_tables;

namespace meow::cypher::symm::DES {
class DESGenRoundKey final : public IGenRoundKey {
  // 1100|1110 => 00|10 => 1|0 => 1 - нечетн
  // 1101|1110 => 00|11 => 1|1 => 0 - четн
  static bool isGoodByte(const std::vector<std::byte>& in) {
    for (const auto& elem : in) {
      auto pre = elem & static_cast<std::byte>(0xFE);
      pre ^= pre >> 4;
      pre ^= pre >> 2;
      pre ^= pre >> 1;

      if ((pre & static_cast<std::byte>(1)) == static_cast<std::byte>(0)) {
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
    static_assert(roundCnt == 16, "16 раундов должно быть");
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    if (inputKey.size() != 8) {
      throw std::runtime_error("ключ должен быть 8 байт == 64 бит");
    }
    // TODO: ТУТ НАДО ДОДЕЛАТЬ ПРОВЕРКУ КЛЮЧА
    if (!isGoodByte(inputKey)) {
      throw std::runtime_error(
          "ключ плохой - проверка на нечетность в байтах не пройдена");
    }

    std::vector res(roundCnt, std::vector<std::byte>(48));

    auto pre = permutate::permutation(inputKey, PC1,
                                      permutate::bitIndexingRule::LSB2MSB, 1);

    // C-старшие 28 бит, D - младшие
    auto C = static_cast<std::uint32_t>(0), D = static_cast<std::uint32_t>(0);

    for (size_t i = 0; i < 3; ++i) {
      C = (C << 8) | (static_cast<std::uint32_t>(pre[i]) & ((1 << 8) - 1));
    }

    C = (C << 4) |
        ((static_cast<std::uint32_t>(pre[3]) & ((1 << 4) - 1) << 4) >> 4);
    D = (static_cast<std::uint32_t>(pre[3]) & (1 << 4) - 1);

    for (size_t i = 0; i < 3; ++i) {
      D = (D << 8) | (static_cast<std::uint32_t>(pre[i]) & ((1 << 8) - 1));
    }

    for (size_t i = 0; i < roundCnt; i++) {
      C = utils::ShiftBytesLeft(static_cast<std::byte>(C), SHIFTS[i], 28);
      D = utils::ShiftBytesLeft(static_cast<std::byte>(D), SHIFTS[i], 28);

      std::vector<std::byte> preBlock(
          7);  // обрезаем по 1 биту 8 раз - там они контрольные
      uint64_t prepre = (C << 28) | (D & 0x0FFFFFFF);
      for (ssize_t j = 6; j >= 0; --j) {
        preBlock[j] = static_cast<std::byte>(prepre & ((1 << 8) - 1));
        prepre >>= 8;
      }

      auto rK = permutate::permutation(preBlock, PC2,
                                       permutate::bitIndexingRule::LSB2MSB, 1);
      res[i] = std::move(rK);
    }

    return res;
  }
};

class DESEncryptionDecryption final : public IEncryptionDecryption {
  /**
   * @brief
   * @param in
   * @return {строка, колонка}
   */
  static std::tuple<uint8_t, uint8_t> _findIxSBlock(const std::byte in) {
    return {
        static_cast<uint8_t>(in & static_cast<std::byte>(0b00100001)),
        static_cast<uint8_t>(in & static_cast<std::byte>(0b00011110)),
    };
  }

 public:
  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    const auto big = permutate::permutation(
        inputBlock, E, permutate::bitIndexingRule::LSB2MSB, 1);
    if (big.size() != roundKey.size()) {
      throw std::runtime_error(
          "размер раундового ключа не совпал с размером расширенного блока (7 "
          "байт)");
    }

    const auto xored = xorSpan(big, roundKey);
    const auto pre_res = {}; // TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    return permutate::permutation(pre_res, P,
                                  permutate::bitIndexingRule::LSB2MSB, 1);
  }
};
}  // namespace meow::cypher::symm::DES

export namespace meow::cypher::symm::DES {
class DES final : public FeistelNet::FeistelNet, ISymmetricCypher {
 public:
  constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) override {
    if (encryptionKey.empty()) {
      throw std::runtime_error("ключик пустой - это плохо");
    }
    if (encryptionKey.size() != 8) {
      throw std::runtime_error("ключик должен юыть 64 бит(или 8 байт)");
    }
    FeistelNet::setRoundKeys(encryptionKey);
  }

  explicit DES(const std::vector<std::byte>& key)
      : FeistelNet(key, 16, std::make_shared<DESGenRoundKey>(16),
                   std::make_shared<DESEncryptionDecryption>()) {};

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    const auto pre =
        permutate::permutation(in, IP, permutate::bitIndexingRule::LSB2MSB, 1);
    const auto encr = FeistelNet::encrypt(pre);
    return permutate::permutation(encr, IP_inv,
                                  permutate::bitIndexingRule::LSB2MSB, 1);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    const auto pre =
        permutate::permutation(in, IP, permutate::bitIndexingRule::LSB2MSB, 1);
    const auto decr = FeistelNet::decrypt(pre);
    return permutate::permutation(decr, IP_inv,
                                  permutate::bitIndexingRule::LSB2MSB, 1);
  }
};
}  // namespace meow::cypher::symm::DES