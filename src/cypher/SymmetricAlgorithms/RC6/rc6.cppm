/**
 * https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf?spm=a2ty_o01.29997173.0.0.78cec921twWyWp&file=RRSY98.pdf
 */
module;

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <vector>

export module cypher.rc6;

import cypher.FeistelNet;
import cypher.utils;
import cypher;

namespace meow::cypher::symm::_detailRC6 {
class RC6GenRoundKey final : public IGenRoundKey {
  static constexpr int32_t w = 32;  // размер слова (блоков 4 => длина блока
                                    // 128бит) odd - округление

  static constexpr uint32_t P =
      0xB7E15163;  // odd((e - 1) * 2^w); e - экспонента ~ 2.718
  static constexpr uint32_t Q =
      0x9E3779B9;  // odd((fi - 1) * 2^w) fi - золотое сечение ~ 1.618

  std::vector<uint32_t> _S;  // таблица ключей, но в числах

 public:
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
    if (inputKey.size() != 16 || inputKey.size() != 24 ||
        inputKey.size() != 32) {
      throw std::runtime_error(
          "ключ должен быть 16/24/32 байт == 128/192/256 бит");
    }

    auto bytesToWords = [](const std::vector<std::byte>& bytes) {
      std::vector<uint32_t> words;
      words.reserve(bytes.size() / 4);

      for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t tmp = 0;
        tmp |=
            static_cast<uint32_t>(static_cast<uint8_t>(bytes[i])) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 1])) << 8) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 2])) << 16) |
            (static_cast<uint32_t>(static_cast<uint8_t>(bytes[i + 3])) << 24);
        words.push_back(tmp);
      }
      return words;
    };

    auto L = bytesToWords(inputKey);                     // байты в цифры
    std::size_t c = std::max<std::size_t>(1, L.size());  // длина

    _S.reserve(2 * roundCnt + 4);  // это будет юзаться

    _S[0] = P;
    for (size_t i = 1; i < _S.size(); ++i) {
      _S[i] = _S[i - 1] + Q;
    }

    uint32_t A = 0;
    uint32_t B = 0;
    std::size_t i = 0;
    std::size_t j = 0;

    size_t n = 3 * std::max(_S.size(), c);
    for (std::size_t k = 0; k < n; ++k) {
      A = _S[i] = utils::ShiftBytesLeft(_S[i] + A + B, 3, 32);
      B = L[j] =
          utils::ShiftBytesLeft(L[j] + A + B, static_cast<int>(A + B) % 32, 32);

      i = (i + 1) % _S.size();
      j = (j + 1) % c;
    }

    std::vector<std::vector<std::byte>> res;
    res.reserve(_S.size());

    for (uint32_t word : _S) {
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

export class RC6EncryptionDecryption final : public IEncryptionDecryption {
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
}  // namespace meow::cypher::symm::_detailRC6

export namespace meow::cypher::symm::RC6 {
class RC6 final : public FeistelNet::FeistelNet {
  RC6()
      : FeistelNet(std::make_shared<_detailRC6::RC6GenRoundKey>(20),
                   std::make_shared<_detailRC6::RC6EncryptionDecryption>()) {};

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    // auto pre =
    //     permutate::permutation(in, IP, permutate::bitIndexingRule::MSB2LSB,
    //     1);
    // auto encr = FeistelNet::encrypt(std::move(pre));
    // return permutate::permutation(std::move(encr), IP_inv,
    //                               permutate::bitIndexingRule::MSB2LSB, 1);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    // auto pre =
    //     permutate::permutation(in, IP, permutate::bitIndexingRule::MSB2LSB,
    //     1);
    // auto decr = FeistelNet::decrypt(std::move(pre));
    // return permutate::permutation(std::move(decr), IP_inv,
    //                               permutate::bitIndexingRule::MSB2LSB, 1);
  }
};
}  // namespace meow::cypher::symm::RC6