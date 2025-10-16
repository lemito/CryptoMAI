/**
 * TODO: ТУТ ШИФРОВАНИЯ ДОДЕЛАТЬ И ВСЯКОЕ РАСПАРАЛЕЛИВАНИЕ/АСИНХРОНЩИНА
 */

module;

#include <algorithm>
#include <any>
// #include <boost/random/mersenne_twister.hpp>
// #include <boost/random/random_device.hpp>
// #include <boost/random/uniform_int_distribution.hpp>
#include <cstddef>
#include <cstdint>
#include <future>
#include <optional>
#include <print>
#include <random>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

export module cypher;

export namespace meow::cypher::symm {
// 1.генерация раундовых ключей
class IGenRoundKey {
 public:
  /**
   * @brief генерируем раундовые ключики из ключика
   * @param inputKey
   * @return
   */
  [[nodiscard]] virtual constexpr std::vector<std::vector<std::byte>>
  genRoundKeys(const std::vector<std::byte>& inputKey) const = 0;

  virtual ~IGenRoundKey() = default;
};

// 2.выполнение шифрующего преобразования
class IEncryptionDecryption {
 public:
  /**
   * @brief шифруемся
   * @param inputBlock
   * @param roundKey
   * @return
   */
  [[nodiscard]] virtual constexpr std::vector<std::byte> encryptDecryptBlock(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const = 0;

  virtual ~IEncryptionDecryption() = default;
};

// 3.(де)шифрование симметричным алгосом БЛОКА
class ISymmetricCypher {
 protected:
  std::vector<std::vector<std::byte>> _roundKeys;
  std::size_t _blockSize = 8;  // размер блока указан в байт (для DES = 8)

 public:
  virtual constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) = 0;

  [[nodiscard]] constexpr decltype(_roundKeys) getRoundKeys() const {
    return _roundKeys;
  }

  [[nodiscard]] virtual constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const = 0;

  [[nodiscard]] virtual constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const = 0;

  virtual ~ISymmetricCypher() = default;
};

enum class encryptionMode : std::int8_t {
  ECB,
  CBC,
  PCBC,
  OFB,
  CTR,
  RandomDelta
};
enum class paddingMode : std::int8_t { Zeros, AnsiX923, PKCS7, ISO10126 };

// 4
class SymmetricCypherContext : public IGenRoundKey,
                               public IEncryptionDecryption,
                               public ISymmetricCypher {
  [[nodiscard]] constexpr std::vector<std::byte> _doPadding(
      const std::vector<std::byte>& in) const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist((0), (255));

    size_t forAdd = _blockSize - in.size() % _blockSize;
    if (forAdd == 0) {
      forAdd = _blockSize;
    }

    std::vector res(_blockSize, static_cast<std::byte>(0));
    std::ranges::copy(in, res.begin());

    switch (_padMode) {
      case paddingMode::Zeros: {
        // ВСЁ ЗАПОЛНЯЕТСЯ НУЛЯМИ
      } break;
      case paddingMode::AnsiX923: {
        // ВСЕ НУЛИ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        res.back() = static_cast<std::byte>(forAdd);
      } break;
      case paddingMode::PKCS7: {
        // ВСЕ ЗАПОЛНЯЕТСЯ КОЛИЧЕСТВОМ ДОБАВЛЕННЫХ БАЙТ
        for (size_t i = in.size(); i < res.size(); ++i) {
          res[i] = static_cast<std::byte>(forAdd);
        }
      } break;
      case paddingMode::ISO10126: {
        // ВСЕ СЛУЧАЙНЫЕ БАЙТЫ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        for (size_t i = in.size(); i < res.size() - 1; ++i) {
          res[i] = static_cast<std::byte>(dist(gen));
        }
        res.back() = static_cast<std::byte>(forAdd);
      } break;
      default:
        throw std::logic_error("нет такого режима набивки");
    }

    return res;
  }

  [[nodiscard]] constexpr std::vector<std::byte> _doUnpadding(
      const std::vector<std::byte>& in) const {
    std::vector<std::byte> res;
    const auto wasAdded = static_cast<size_t>(in.back());

    switch (_padMode) {
      case paddingMode::Zeros:
        // ВСЁ ЗАПОЛНЯЕТСЯ НУЛЯМИ
        {
          size_t i = in.size();
          for (; i > 0 && in[i] == static_cast<std::byte>(0); --i) {
          }
          res = std::move(std::vector(in.begin(), in.begin() + i));
        }
        break;
      case paddingMode::AnsiX923:  // ВСЕ НУЛИ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО
                                   // ДОБАВЛЕННЫХ БАЙТ
      {
        for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
          if (in[i] != static_cast<std::byte>(0)) {
            throw std::runtime_error("в AnsiX923 должны быть нули байты");
          }
        }
        auto pre_res = in | std::views::take(in.size() - wasAdded);
        res = std::move(std::vector(pre_res.begin(), pre_res.end()));
      } break;
      case paddingMode::PKCS7:
        // ВСЕ ЗАПОЛНЯЕТСЯ КОЛИЧЕСТВОМ ДОБАВЛЕННЫХ БАЙТ
        {
          for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
            if (in[i] != static_cast<std::byte>(wasAdded)) {
              throw std::runtime_error("в PKCS7 должны быть одинаковые байты");
            }
          }
          auto pre_res = in | std::views::take(in.size() - wasAdded);
          res = std::move(std::vector(pre_res.begin(), pre_res.end()));
        }
        break;
      case paddingMode::ISO10126:
        // ВСЕ СЛУЧАЙНЫЕ БАЙТЫ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        {
          auto pre_res = in | std::views::take(in.size() - wasAdded);
          res = std::move(std::vector(pre_res.begin(), pre_res.end()));
        }
        break;
      default:
        throw std::logic_error("нет такого режима набивки");
    }

    return res;
  }

 protected:
  std::vector<std::byte> _encryptionKey;
  encryptionMode _encMode;
  paddingMode _padMode;
  std::optional<std::vector<std::byte>> _init_vec;
  std::vector<std::any> _params;
  std::vector<std::vector<std::byte>> _roundKeys;

  // [[nodiscard]] std::future<std::vector<std::byte>> _encryptAsync(
  //     const std::vector<std::byte>& in) const {
  //   return std::async(std::launch::async,
  //                     [this, &in] { return std::vector<std::byte>{}; });
  // }
  //
  // std::future<void> _encryptAsync(const std::string& inFilePath,
  //                                 const std::string& resFilePath) const {}
  //
  // [[nodiscard]] std::future<std::vector<std::byte>> _decryptAsync(
  //     const std::vector<std::byte>& in) const {
  //   return std::async(std::launch::async,
  //                     [this, &in] { return std::vector<std::byte>{}; });
  // }

  // std::future<void> _decryptAsync(const std::string& inFilePath,
  //                                 const std::string& resFilePath) const {}

 public:
  constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) override {
    _roundKeys = std::move(genRoundKeys(encryptionKey));
  }

  template <typename... Args>
  SymmetricCypherContext(
      const std::vector<std::byte>& encryptionKey, const encryptionMode encMode,
      const paddingMode padMode,
      const std::optional<std::vector<std::byte>>& init_vec = std::nullopt,
      Args&&... params)
      : _encryptionKey(encryptionKey),
        _encMode(encMode),
        _padMode(padMode),
        _init_vec(init_vec),
        _params(std::forward<Args>(params)...) {}

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    return {};
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    return {};
  }

  constexpr void encrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) const {}

  constexpr void decrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) const {}
};
}  // namespace meow::cypher::symm
