module;
export module cypher.rc6;

import cypher.FeistelNet;
import cypher.utils;
import cypher;

namespace meow::cypher::symm::_detailRC6 {
class RC6GenRoundKey final : public IGenRoundKey {
 public:
  explicit RC6GenRoundKey(const size_t RoundCnt) : IGenRoundKey(RoundCnt) {}
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

    // TODO: !!! про разные ключи не забыть!

    return res;
  }
};

export class RC6EncryptionDecryption final : public IEncryptionDecryption {
 public:
  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    if (big.size() != roundKey.size()) {
      throw std::runtime_error(
          "размер раундового ключа не совпал с размером расширенного блока "
          "(ожидается 6 байт / 48 бит)");
    }
    // TODO:
  }
};
}  // namespace meow::cypher::symm::_detailRC6

export namespace meow::cypher::symm::RC6 {
class RC6 final : public FeistelNet::FeistelNet {
  RC6()
      : FeistelNet(std::make_shared<_detailRC6::RC6GenRoundKey>(16),
                   std::make_shared<_detailRC6::RC6EncryptionDecryption>()) {};

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
}  // namespace meow::cypher::symm::RC6