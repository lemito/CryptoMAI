module;

#include <any>
#include <cstddef>
#include <cstdint>
#include <future>
#include <optional>
#include <print>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
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
  [[nodiscard]] virtual constexpr std::vector<std::byte> encrypt_decrypt(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const = 0;

  virtual ~IEncryptionDecryption() = default;
};

// 3.(де)шифрование симметричным алгосом БЛОКА
class ISymmetricCypher {
 protected:
  std::vector<std::vector<std::byte>> _roundKeys;

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
 protected:
  std::vector<std::byte> _encryptionKey;
  encryptionMode _encMode;
  paddingMode _padMode;
  std::optional<std::vector<std::byte>> _init_vec;
  std::vector<std::any> _params;
  std::vector<std::vector<std::byte>> _roundKeys;

  [[nodiscard]] std::future<std::vector<std::byte>> _encryptAsync(
      const std::vector<std::byte>& in) const {
    return std::async(std::launch::async,
                      [this, &in] { return std::vector<std::byte>{}; });
  }

  std::future<void> _encryptAsync(const std::string& inFilePath,
                                  const std::string& resFilePath) const {}

  [[nodiscard]] std::future<std::vector<std::byte>> _decryptAsync(
      const std::vector<std::byte>& in) const {
    return std::async(std::launch::async,
                      [this, &in] { return std::vector<std::byte>{}; });
  }

  std::future<void> _decryptAsync(const std::string& inFilePath,
                                  const std::string& resFilePath) const {}

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
    return _encryptAsync(in).get();
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    return _decryptAsync(in).get();
  }
};
}  // namespace meow::cypher::symm
