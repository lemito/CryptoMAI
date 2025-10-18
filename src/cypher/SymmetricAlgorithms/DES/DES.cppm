/**
 * https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 */
module;

#include <vector>

export module DES;

import cypher.FeistelNet;
import cypher.utils;
import cypher;
import cypher.DES.des_tables;

namespace meow::cypher::symm::DES {
class DESGenRoundKey final : public IGenRoundKey {
 public:
  DESGenRoundKey() : IGenRoundKey(16) {};
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

class DESEncryptionDecryption : public IEncryptionDecryption {};
}  // namespace meow::cypher::symm::DES

export namespace meow::cypher::symm::DES {
class DES final : public ISymmetricCypher {
 public:
};
}  // namespace meow::cypher::symm::DES