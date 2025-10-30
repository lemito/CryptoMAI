module;

#include <bit>
#include <iostream>

#include "debug.h"

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
  BadDEALKey() = default;
  explicit BadDEALKey(const std::string&) {}
  [[nodiscard]] const char* what() const noexcept override {
    return "Плохой ключ - нечетность всех 8 байт в каждом бите не выполнена";
  }
};

namespace meow::cypher::symm::_detailDEAL {
class DEALGenRoundKey final : public IGenRoundKey {
  std::shared_ptr<DES::DES> _des{};

 public:
  explicit DEALGenRoundKey(const size_t RoundCnt, std::shared_ptr<DES::DES> d)
      : IGenRoundKey(RoundCnt), _des(d) {
    if (d == nullptr) {
      throw std::runtime_error(
          "des алгоритм не установился, работать не буду! (DEALGenRoundKey())");
    }
  }
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] constexpr std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) override {
    if (inputKey.empty()) {
      throw std::runtime_error(
          "ключ не должен быть пустым - нельзя по нему составить раундовые ");
    }
    if (_des == nullptr) {
      throw std::runtime_error(
          "des алгоритм не установился, работать не буду! (genRoundKeys)");
    }

    switch (const size_t keySiz = inputKey.size()) {
        // 128 бит; 2 des
      case 16:
        this->roundCnt = 6;
        break;
        // 192 бит; 3 des
      case 24:
        this->roundCnt = 6;
        break;
        // 256 бит; 4 des
      case 32:
        this->roundCnt = 8;
        break;
      default:
        throw std::invalid_argument("ключ может быть только 128/192/256 бит");
    }

    std::vector<std::vector<std::byte>> keys(this->roundCnt);
    for (size_t i = 0; i < roundCnt; i++) {
      keys[i] = std::vector<std::byte>(inputKey.begin() + i * 8,
                                       inputKey.begin() + (i + 1) * 8);
    }

    // TODO: либо вики врет, либо начальный ключ 0x0123456789abcedf; так как
    // будто это плохой ключик; поэтому начальным ключом будет часть ориг ключа
#ifndef DEBUG
    std::vector<std::byte> K0(inputKey.begin(), inputKey.begin() + 8);
#endif
    const std::vector<std::byte> K0{
        static_cast<std::byte>(0x01), static_cast<std::byte>(0x23),
        static_cast<std::byte>(0x45), static_cast<std::byte>(0x67),
        static_cast<std::byte>(0x89), static_cast<std::byte>(0xab),
        static_cast<std::byte>(0xcd), static_cast<std::byte>(0xef),
    };

    _des->setRoundKeys(K0);

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

      auto R = xorSpan(std::move(bytes), res[i - 1]);
      auto L = xorSpan(keys[i % roundCnt], std::move(R));
      res[i] = _des->encrypt(std::move(L));
    }

    return res;
  }
};

export class DEALEncryptionDecryption final : public IEncryptionDecryption {
 public:
  std::shared_ptr<DES::DES> _des{};

  explicit DEALEncryptionDecryption(std::shared_ptr<DES::DES> d) : _des(d) {
    if (_des == nullptr) {
      throw std::runtime_error(
          "des алгоритм не установился, работать не буду! "
          "(DEALEncryptionDecryption())");
    }
  }

  [[nodiscard]] constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const override {
    if (_des == nullptr) {
      throw std::runtime_error(
          "des алгоритм не установился, работать не буду! "
          "(encryptDecryptBlock)");
    }

    if (inputBlock.size() != 8) {
      throw std::invalid_argument("размер блока должен быть 8 байт для DES");
    }

    if (roundKey.size() != 8) {
      throw std::invalid_argument("размер ключа раунда должен быть 8 байт");
    }
    _des->setRoundKeys(roundKey);
    _des->_roundKeys = std::move(_des->getRoundKeys());

    return _des->encrypt(inputBlock);
  }
};
}  // namespace meow::cypher::symm::_detailDEAL

namespace meow::cypher::symm::DEAL {

export class DEAL final : public FeistelNet::FeistelNet {
 public:
  std::size_t _blockSize = 16;
  std::shared_ptr<DES::DES> _des{};

  DEAL(std::shared_ptr<DES::DES> d)
      : FeistelNet(std::make_shared<_detailDEAL::DEALGenRoundKey>(16, d),
                   std::make_shared<_detailDEAL::DEALEncryptionDecryption>(d)),
        _des(d) {}

  // void setRoundKeys(const std::vector<std::byte>& key) override {
  //   if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
  //     throw BadDEALKey("Ключ DEAL должен быть 128, 192 или 256 бит");
  //   }
  //
  //   FeistelNet::setRoundKeys(key);
  //
  // }

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    if (_des == nullptr) {
      throw std::runtime_error("des не смог прийти в DEAL");
    }

    return _des->encrypt(in);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    if (_des == nullptr) {
      throw std::runtime_error("des не смог прийти в DEAL");
    }
    return _des->decrypt(in);
  }
};

export class DEALAdapter final : public ISymmetricCypher {
  std::shared_ptr<DES::DES> _des{};
  std::unique_ptr<DEAL> _deal{};

 public:
  DEALAdapter() {
    _des = std::make_shared<DES::DES>();
    _deal = std::make_unique<DEAL>(_des);
  }

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    if (_deal == nullptr) {
      throw std::runtime_error("deal не смог создаться");
    }
    return _deal->encrypt(in);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    if (_deal == nullptr) {
      throw std::runtime_error("deal не смог создаться");
    }
    return _deal->decrypt(in);
  }

  constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) override {
    if (_deal == nullptr) {
      throw std::runtime_error("deal не смог создаться");
    }

    _deal->setRoundKeys(encryptionKey);
    _roundKeys = std::move(_deal->getRoundKeys());
  };
};
}  // namespace meow::cypher::symm::DEAL