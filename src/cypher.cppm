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

// import <vector>;
// import <cstddef>;
// import <optional>;
// import <unordered_map>;
// import <variant>;
// import <string>;
// import <future>;
// import <print>;

export module cypher;

// генерация раундовых ключей
class IGenRoundKey {
 public:
  [[nodiscard]] virtual std::vector<std::vector<std::byte>> generateRoundKeys(
      const std::vector<std::byte>& inputKey) const = 0;

  virtual ~IGenRoundKey() = default;
};

// выполнение шифрующего преобразования
class IEncryption {
 public:
  [[nodiscard]] virtual std::vector<std::byte> genRoundKeys(
      const std::vector<std::byte>& inputBlock,
      const std::vector<std::byte>& roundKey) const = 0;

  virtual ~IEncryption() = default;
};

// (де)шифрование симметричным алгосом
class ISymmetricCypher {
 public:
  virtual void encrypt(const std::vector<std::byte>& block,
                       const std::vector<std::byte>& roundKey,
                       std::vector<std::byte>& res) const = 0;
  virtual void decrypt(const std::vector<std::byte>& block,
                       const std::vector<std::byte>& roundKey,
                       std::vector<std::byte>& res) const = 0;

  virtual void setRoundKeys(const std::vector<std::byte>& encryptionKey) = 0;

  virtual ~ISymmetricCypher() = default;
};

export enum class encryptionMode : int8_t {
  ECB,
  CBC,
  PCBC,
  OFB,
  CTR,
  RandomDelta
};
export enum class paddingMode : int8_t { Zeros, AnsiX923, PKCS7, ISO10126 };
export using Param =
    std::variant<std::monostate, int32_t, int64_t, size_t,
                 std::vector<std::byte>, char, std::byte, std::string, bool>;

export class ParamContainer {
  std::unordered_map<std::string, Param> params;

 public:
  auto contains(const std::string& key) const -> bool {
    return params.contains(key);
  }

  auto find(const std::string& key) const -> std::optional<Param> {
    if (const auto it = params.find(key); it != params.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  void set(const std::string& key, const Param& val) {
    params.emplace(key, val);
  }
};

//
export class SymmetricCypher : public ISymmetricCypher {
  std::vector<std::byte> _encryptionKey;
  encryptionMode _encMode;
  paddingMode _padMode;
  std::optional<std::vector<std::byte>> _init_vec;
  ParamContainer _params;

  void setRoundKeys(const std::vector<std::byte>& encryptionKey) override {
    throw std::runtime_error("НАДО ДОДЕЛАТЬ");
  }

 public:
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
                            std::vector<std::byte>& res);
  std::future<void> encrypt(const std::string& inputPath,
                            const std::string& outputPath);
  std::future<void> decrypt(const std::vector<std::byte>& in,
                            std::vector<std::byte>& res);
  std::future<void> decrypt(const std::string& inputPath,
                            const std::string& outputPath);
};

export void test_module() { std::print("Meow\n"); }
