module;

#include <vector>
#include <cstddef>
#include <stdexcept>
#include <cassert>
#include <memory>

export module cypher.loki97;

import cypher.FeistelNet;
import cypher.utils;
import cypher;

namespace meow::cypher::symm::_detailLOKI97 {
class LOKI97GenRoundKey final : public IGenRoundKey {
 public:
  explicit LOKI97GenRoundKey(const size_t RoundCnt) : IGenRoundKey(RoundCnt) {}
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] constexpr std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) override {
    assert(roundCnt == 16);
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    if (inputKey.size() != 8) {
      throw std::runtime_error("ключ должен быть 8 байт == 64 бит");
    }
    std::vector<std::vector<std::byte>> res;

    // TODO: !!! про разные ключи не забыть!

    return res;
  }
};

export class LOKI97EncryptionDecryption final : public IEncryptionDecryption {
 public:
  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    // if (big.size() != roundKey.size()) {
    //   throw std::runtime_error(
    //       "размер раундового ключа не совпал с размером расширенного блока "
    //       "(ожидается 6 байт / 48 бит)");
    // }
    // TODO:
  }
};
}  // namespace meow::cypher::symm::_detailLOKI97

export namespace meow::cypher::symm::LOKI97 {
class LOKI97 final : public FeistelNet::FeistelNet {
  LOKI97()
      : FeistelNet(
            std::make_shared<_detailLOKI97::LOKI97GenRoundKey>(16),
            std::make_shared<_detailLOKI97::LOKI97EncryptionDecryption>()) {};

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {

  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
 
  }
};
}  // namespace meow::cypher::symm::LOKI97