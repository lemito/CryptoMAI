module;
#include <unistd.h>

#include <bit>
#include <cassert>
#include <iomanip>
#include <ios>
#include <iostream>

export module cypher.DEAL;
import <cstdint>;
import <array>;
import <cstddef>;
import <memory>;
import <span>;
import <stdexcept>;
import <tuple>;
import <vector>;

import cypher.utils;
import cypher.FeistelNet;
import cypher.DES;
import cypher;

export class BadDEALKey final : public std::exception {
 public:
  BadDEALKey() {}
  explicit BadDEALKey(const std::string&) {}
  const char* what() const noexcept override {
    return "Плохой ключ - нечетность всех 8 байт в каждом бите не выполнена";
  }
};

namespace meow::cypher::symm::_detailDEAL {
class DEALGenRoundKey final : public IGenRoundKey {
  mutable std::shared_ptr<DES::DES> _des{};

 public:
  explicit DEALGenRoundKey(const size_t RoundCnt) : IGenRoundKey(RoundCnt) {}
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] constexpr std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) const override {
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    switch (const size_t keySiz = inputKey.size()) {
      case 16:
        this->roundCnt = 6;
        break;
      case 24:
        this->roundCnt = 6;
        break;
      case 32:
        this->roundCnt = 8;
        break;
      default:
        throw std::invalid_argument("ключ может быть только 128/192/256 бит");
    }

    _des = std::make_shared<DES::DES>();
    const std::vector<std::byte> desKey(inputKey.begin(), inputKey.begin() + 8);
    _des->setRoundKeys(desKey);

    std::vector<std::vector<std::byte>> keys(this->roundCnt);
    for (size_t i = 0; i < roundCnt; i++) {
      keys[i] = std::vector<std::byte>(inputKey.begin() + i * 8,
                                       inputKey.begin() + (i + 1) * 8);
    }

    std::vector<std::vector<std::byte>> res(roundCnt);

    res[0] = _des->encrypt(keys[0]);
    auto pre = xorSpan(keys[1], res[0]);
    res[1] = _des->encrypt(std::move(pre));

    for (size_t i = 2; i < roundCnt; ++i) {
      uint64_t I = 1ULL << (64 - (1ULL << (i - 2)));
      std::vector<std::byte> bytes(8);
      for (int j = 7; j >= 0; --j) {
        bytes[j] = static_cast<std::byte>(I & 0xFF);
        I >>= 8;
      }
      auto R = xorSpan(bytes, res[i - 1]);
      auto L = xorSpan(keys[i % roundCnt], std::move(R));
      res[i] = _des->encrypt(std::move(L));
    }

    return res;
  }
};

export class DEALEncryptionDecryption final : public IEncryptionDecryption {
 public:
  std::shared_ptr<DES::DES> _des{};

  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    _des->setRoundKeys(roundKey);
    return _des->encrypt(inputBlock);
  }
};
}  // namespace meow::cypher::symm::_detailDEAL

namespace meow::cypher::symm::DEAL {
export class DEAL final : public FeistelNet::FeistelNet {
 public:
  std::size_t _blockSize = 16;
  DEAL()  // 16 тут заглушка, roundCnt и все такое определится позже
      : FeistelNet(std::make_shared<_detailDEAL::DEALGenRoundKey>(16),
                   std::make_shared<_detailDEAL::DEALEncryptionDecryption>()) {
        };

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    return FeistelNet::encrypt(in);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    return FeistelNet::decrypt(in);
  }
};
}  // namespace meow::cypher::symm::DEAL