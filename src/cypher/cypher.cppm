module;

#include <cstddef>
#include <future>
#include <optional>
#include <print>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

export module cypher;

namespace meow::cypher {
// генерация раундовых ключей
class IGenRoundKey {
 public:
  [[nodiscard]] virtual std::vector<std::vector<std::byte>> genRoundKeys(
      const std::vector<std::byte>& inputKey) const = 0;

  virtual ~IGenRoundKey() = default;
};

// выполнение шифрующего преобразования
class IEncryption {
 public:
  [[nodiscard]] virtual std::vector<std::byte> encrypt(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const = 0;

  virtual ~IEncryption() = default;
};

// (де)шифрование симметричным алгосом
class ISymmetricCypher {
 public:
  virtual void setRoundKeys(const std::vector<std::byte>& encryptionKey) = 0;

  virtual std::future<void> encrypt(const std::vector<std::byte>& in,
                                    std::vector<std::byte>& res) const = 0;

  virtual std::future<void> decrypt(const std::vector<std::byte>& in,
                                    std::vector<std::byte>& res) const = 0;

  virtual std::future<void> encrypt(const std::string& inputPath,
                                    const std::string& outputPath) const = 0;

  virtual std::future<void> decrypt(const std::string& inputPath,
                                    const std::string& outputPath) const = 0;

  virtual ~ISymmetricCypher() = default;
};

export enum class encryptionMode : std::int8_t {
  ECB,
  CBC,
  PCBC,
  OFB,
  CTR,
  RandomDelta
};
export enum class paddingMode : std::int8_t {
  Zeros,
  AnsiX923,
  PKCS7,
  ISO10126
};
export using Param =
    std::variant<std::monostate, std::int32_t, std::int64_t, std::size_t,
                 std::vector<std::byte>, char, std::byte, std::string, bool>;

export class ParamContainer {
  std::unordered_map<std::string, Param> _params;

 public:
  auto contains(const std::string& key) const -> bool {
    return _params.contains(key);
  }

  auto find(const std::string& key) const -> std::optional<Param> {
    if (const auto it = _params.find(key); it != _params.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  void set(const std::string& key, const Param& val) {
    _params.insert({key, val});
  }
};

//
export class SymmetricCypher : public IGenRoundKey,
                               public IEncryption,
                               public ISymmetricCypher {
  std::vector<std::byte> _encryptionKey;
  encryptionMode _encMode;
  paddingMode _padMode;
  std::optional<std::vector<std::byte>> _init_vec;
  ParamContainer _params;
  std::vector<std::vector<std::byte>> _roundKeys;

 public:
  void setRoundKeys(const std::vector<std::byte>& encryptionKey) override {}

  SymmetricCypher(
      const std::vector<std::byte>& encryptionKey, const encryptionMode encMode,
      const paddingMode padMode,
      const std::optional<std::vector<std::byte>>& init_vec = std::nullopt,
      ParamContainer params = {})
      : _encryptionKey(encryptionKey),
        _encMode(encMode),
        _padMode(padMode),
        _init_vec(init_vec),
        _params(std::move(params)) {
    SymmetricCypher::setRoundKeys(encryptionKey);
  };

  std::future<void> encrypt(const std::vector<std::byte>& in,
                            std::vector<std::byte>& res) const override {
    throw std::runtime_error("НАДО СДЕЛАТЬ!!!");
  }

  std::future<void> encrypt(const std::string& inputPath,
                            const std::string& outputPath) const override {
    throw std::runtime_error("НАДО СДЕЛАТЬ!!!");
  }

  std::future<void> decrypt(const std::vector<std::byte>& in,
                            std::vector<std::byte>& res) const override {
    throw std::runtime_error("НАДО СДЕЛАТЬ!!!");
  }

  std::future<void> decrypt(const std::string& inputPath,
                            const std::string& outputPath) const override {
    throw std::runtime_error("НАДО СДЕЛАТЬ!!!");
  }
};
export void test_module() { std::print("Meow\n"); }
}  // namespace meow::cypher
