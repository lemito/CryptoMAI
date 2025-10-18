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
#include <fstream>
#include <future>
#include <memory>
#include <optional>
#include <print>
#include <random>
#include <ranges>
#include <utility>
#include <vector>

export module cypher;

export namespace meow::cypher::symm {
// 1.генерация раундовых ключей
class IGenRoundKey {
 public:
  size_t roundCnt = 0;
  explicit IGenRoundKey(const size_t cnt) : roundCnt(cnt) {}

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

// https://www.geeksforgeeks.org/ethical-hacking/block-cipher-modes-of-operation
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
// поведение блоков между собой
enum class encryptionMode : std::int8_t {
  // Electronic Codebook - независимо шифруемся; можно пар
  ECB,
  // Cipher Block Chaining - блок перед шифрование ^ с предыдущим; не пар
  CBC,
  // PropagatingCipherBlockChaining - как CBC?
  PCBC,
  // Cipher Feedback - блочный как потоковый, нелья параллелить
  CFB,
  // Output Feedback
  OFB,
  // Counter - счетчик; можно паралелить
  CTR,
  // к ьлоку добавляется какое-то значение
  RandomDelta
};
// набивка
enum class paddingMode : std::int8_t {
  // ВСЁ ЗАПОЛНЯЕТСЯ НУЛЯМИ
  Zeros,
  // нули, кроме ластового
  AnsiX923,
  // ВСЕ ЗАПОЛНЯЕТСЯ КОЛИЧЕСТВОМ ДОБАВЛЕННЫХ БАЙТ
  PKCS7,
  // ранд, кроме ласт
  ISO10126
};

// 4
class SymmetricCypherContext {
 protected:
  static constexpr size_t BATCH_SIZE = 4096;
  std::size_t _blockSize = 8;  // размер блока указан в байт (для DES = 8)
 private:
  enum class ACTION_MODE : int8_t { encrypt, decrypt };
  constexpr void _processFile(const ACTION_MODE& mode,
                              const std::string& inPath,
                              const std::string& destPath) const {
    std::ifstream i_file(inPath, std::ios::binary);
    if (!i_file) {
      throw std::runtime_error("не удалось открыть входной файл");
    }
    std::ofstream o_file(destPath, std::ios::binary | std::ios::app);
    if (!o_file) {
      throw std::runtime_error("не удалось открыть выходной файл");
    }

    std::vector<std::byte> buffer(BATCH_SIZE);

    while (i_file) {
      i_file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
      std::streamsize read = i_file.gcount();

      if (read == 0) {
        break;
      }

      std::vector<std::byte> write_buf(read);
      mode == ACTION_MODE::encrypt ? encrypt(write_buf, buffer)
                                   : decrypt(write_buf, buffer);

      o_file.write(reinterpret_cast<const char*>(write_buf.data()),
                   write_buf.size());
    }
  }

  [[nodiscard]] std::vector<std::byte> _processECB(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      const std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());

    std::vector<std::future<void>> futures;
    futures.reserve(blockCnt);

    for (std::size_t i = 0; i < blockCnt; i++) {
      futures.push_back(
          std::async(std::launch::async, [this, &in, &res, i, &mode]() {
            const size_t off = i * _blockSize;
            auto pre_res =
                mode == ACTION_MODE::encrypt
                    ? this->_algo->encrypt(
                          {in.begin() + off, in.begin() + off + _blockSize})
                    : this->_algo->decrypt(
                          {in.begin() + off, in.begin() + off + _blockSize});
            std::ranges::copy(pre_res, res.begin() + off);
          }));
    }

    for (auto& f : futures) {
      f.get();
    }

    return res;
  }
  [[nodiscard]] std::vector<std::byte> _processCBC(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;
  [[nodiscard]] std::vector<std::byte> _processPCBC(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;
  [[nodiscard]] std::vector<std::byte> _processCFB(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;
  [[nodiscard]] std::vector<std::byte> _processOFB(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;
  [[nodiscard]] std::vector<std::byte> _processCTR(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;
  [[nodiscard]] std::vector<std::byte> _processRandomDelta(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const;

  [[nodiscard]] constexpr std::future<std::vector<std::byte>> _processBlock(
      const ACTION_MODE mode, const std::vector<std::byte>& in) const {
    return std::async(std::launch::async, [&, this] {
      const auto padded = _doPadding(in);
      const std::size_t blockCnt = padded.size() / _blockSize;

      switch (_encMode) {
        case encryptionMode::ECB:
          return _processECB(mode, padded, blockCnt);

        case encryptionMode::CBC:
          return _processCBC(mode, padded, blockCnt);

        case encryptionMode::PCBC:
          return _processPCBC(mode, padded, blockCnt);

        case encryptionMode::CFB:
          return _processCFB(mode, padded, blockCnt);

        case encryptionMode::OFB:
          return _processOFB(mode, padded, blockCnt);

        case encryptionMode::CTR:
          return _processCTR(mode, padded, blockCnt);

        case encryptionMode::RandomDelta:
          return _processRandomDelta(mode, padded, blockCnt);

        default:
          break;
      }

      throw std::runtime_error("ошибочка при обработке блока");
    });
  }

  [[nodiscard]] constexpr std::vector<std::byte> _doPadding(
      const std::vector<std::byte>& in) const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist((0), (255));

    uint8_t forAdd = _blockSize - in.size() % _blockSize;
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
    const auto wasAdded = static_cast<uint8_t>(in.back());
    const auto findSizAndRemove = [&in, &res, &wasAdded] {
      auto pre_res = in | std::views::take(in.size() - wasAdded);
      res = std::move(std::vector(pre_res.begin(), pre_res.end()));
    };

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
      case paddingMode::AnsiX923:
        // ВСЕ НУЛИ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        {
          for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
            if (in[i] != static_cast<std::byte>(0)) {
              throw std::runtime_error("в AnsiX923 должны быть нули байты");
            }
          }
          findSizAndRemove();
        }
        break;
      case paddingMode::PKCS7:
        // ВСЕ ЗАПОЛНЯЕТСЯ КОЛИЧЕСТВОМ ДОБАВЛЕННЫХ БАЙТ
        {
          for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
            if (in[i] != static_cast<std::byte>(wasAdded)) {
              throw std::runtime_error("в PKCS7 должны быть одинаковые байты");
            }
          }
          findSizAndRemove();
        }
        break;
      case paddingMode::ISO10126:
        // ВСЕ СЛУЧАЙНЫЕ БАЙТЫ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        {
          findSizAndRemove();
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
  std::shared_ptr<ISymmetricCypher> _algo;

 public:
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

  template <typename... Args>
  SymmetricCypherContext(
      const std::shared_ptr<ISymmetricCypher>& algo,
      const std::vector<std::byte>& encryptionKey, const encryptionMode encMode,
      const paddingMode padMode,
      const std::optional<std::vector<std::byte>>& init_vec = std::nullopt,
      Args&&... params)
      : _encryptionKey(encryptionKey),
        _encMode(encMode),
        _padMode(padMode),
        _init_vec(init_vec),
        _params(std::forward<Args>(params)...) {
    setAlgo(algo);
  }

  constexpr void setAlgo(const std::shared_ptr<ISymmetricCypher>& algo) {
    if (algo == nullptr) {
      throw std::runtime_error("у тебя указатель пустой на алгоритм");
    }
    if (_encryptionKey.empty()) {
      throw std::runtime_error("");
    }
    _algo = algo;
    _algo->setRoundKeys(_encryptionKey);
  }

  constexpr void encrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) const {
    if (_algo == nullptr) {
      throw std::runtime_error(
          "алгоритм шифрования/дешифрования не установлен. воспользуйся "
          "методом setAlgo");
    }
    if (_encryptionKey.empty()) {
      throw std::runtime_error("ключ должен быть не пустым");
    }
    if (_roundKeys.empty()) {
      throw std::runtime_error("рандовые ключи пусты, проверь ключ");
    }
    // TODO: ляляля тут шифрование
    dest = _processBlock(ACTION_MODE::encrypt, in).get();
  }

  constexpr void encrypt(std::vector<std::byte>& dest,
                         std::span<std::byte> in) const {
    std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
    vec.assign(in.begin(), in.end());
    this->encrypt(dest, vec);
  }

  constexpr void decrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) const {
    if (_algo == nullptr) {
      throw std::runtime_error(
          "алгоритм шифрования/дешифрования не установлен. воспользуйся "
          "методом setAlgo");
    }
    if (_encryptionKey.empty()) {
      throw std::runtime_error("ключ должен быть не пустым");
    }
    if (_roundKeys.empty()) {
      throw std::runtime_error("рандовые ключи пусты, проверь ключ");
    }
    // TODO: ляляля тут дешифрование
    dest = _processBlock(ACTION_MODE::decrypt, in).get();
  }

  constexpr void decrypt(std::vector<std::byte>& dest,
                         std::span<std::byte> in) const {
    std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
    vec.assign(in.begin(), in.end());
    this->decrypt(dest, vec);
  }

  constexpr void encrypt(const std::string& destPath,
                         const std::string& inPath) const {
    _processFile(ACTION_MODE::encrypt, inPath, destPath);
  }

  constexpr void decrypt(const std::string& destPath,
                         const std::string& inPath) const {
    _processFile(ACTION_MODE::decrypt, inPath, destPath);
  }
};
}  // namespace meow::cypher::symm
