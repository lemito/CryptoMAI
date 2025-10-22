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

export std::vector<std::byte> xorSpan(const std::vector<std::byte>& a,
                                      const std::vector<std::byte>& b) {
  if (a.size() != b.size()) {
    throw std::runtime_error("блоки должны быть одного размера");
  }
  const auto pre_res = std::ranges::views::zip(a, b) |
                       std::ranges::views::transform([](auto pair) {
                         auto [x, y] = pair;
                         return x ^ y;
                       });

  return {pre_res.begin(), pre_res.end()};
}

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

 public:
  std::size_t _blockSize = 8;  // размер блока указан в байт (для DES = 8)

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
 private:
  enum class ACTION_MODE : int8_t { encrypt, decrypt, encrUpad, decrUnpad };
  void _processFile(const ACTION_MODE& mode, const std::string& inPath,
                    const std::string& destPath) {
    std::ifstream i_file(inPath, std::ios::binary);
    if (!i_file) {
      throw std::runtime_error("не удалось открыть входной файл");
    }
    std::ofstream o_file(destPath, std::ios::binary | std::ios::trunc);
    if (!o_file) {
      throw std::runtime_error("не удалось открыть выходной файл");
    }

    const size_t block_size = this->_algo->_blockSize;
    std::vector<std::byte> read_buffer(1024 * block_size);

    while (i_file.read(reinterpret_cast<char*>(read_buffer.data()),
                       read_buffer.size())) {
      auto result =
          mode == ACTION_MODE::encrypt
              ? _processBlock(ACTION_MODE::encrUpad, read_buffer).get()
              : _processBlock(ACTION_MODE::decrUnpad, read_buffer).get();
      o_file.write(reinterpret_cast<const char*>(result.data()), result.size());

      if (!o_file) {
        throw std::runtime_error("ошибка записи в выходной файл");
      }
    }

    if (std::streamsize bytes_read = i_file.gcount(); bytes_read > 0) {
      read_buffer.resize(bytes_read);
      auto result = _processBlock(mode, std::move(read_buffer)).get();
      o_file.write(reinterpret_cast<const char*>(result.data()), result.size());

      if (!o_file) {
        throw std::runtime_error("ошибка записи в выходной файл");
      }
    }
  }

  [[nodiscard]] std::vector<std::byte> _processECB(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      const std::size_t blockCnt) const {
    if (in.size() != blockCnt * this->_algo->_blockSize) {
      throw std::invalid_argument("размер блока не подходит для алгоритма");
    }

    std::vector<std::byte> res(in.size());

    std::vector<std::future<void>> futures;
    futures.reserve(blockCnt);

    for (std::size_t i = 0; i < blockCnt; i++) {
      futures.push_back(
          std::async(std::launch::async, [this, &in, &res, i, &mode]() {
            const size_t off = i * this->_algo->_blockSize;
            std::vector block(in.begin() + off,
                              in.begin() + off + this->_algo->_blockSize);

            // std::vector<std::byte> proc_block;
            if (mode == ACTION_MODE::encrypt) {
              block = std::move(this->_algo->encrypt(block));
            } else {
              block = std::move(this->_algo->decrypt(block));
            }

            std::ranges::copy(block, res.begin() + off);
          }));
    }

    for (auto& f : futures) {
      f.get();
    }

    return res;
  }

  [[nodiscard]] std::vector<std::byte> _processCBC(
      const ACTION_MODE mode, const std::vector<std::byte>& in,
      const std::size_t blockCnt) const {
    if (in.size() != blockCnt * this->_algo->_blockSize) {
      throw std::invalid_argument("размер блока не подходит для алгоритма");
    }
    if (!_init_vec.has_value()) {
      throw std::runtime_error("IV пуст");
    }

    std::vector<std::byte> res(in.size());
    auto prev = _init_vec.value();
    if (prev.size() != this->_algo->_blockSize) {
      throw std::runtime_error(
          "Размер вектора инициализации не соответствует размеру блока");
    }
    if (mode == ACTION_MODE::encrypt) {
      for (std::size_t i = 0; i < blockCnt; i++) {
        std::vector block(in.begin() + i * this->_algo->_blockSize,
                          in.begin() + (i + 1) * this->_algo->_blockSize);

        if (block.size() != prev.size()) {
          throw std::runtime_error("блоки должны быть одного размера");
        }

        auto xored = xorSpan(std::move(block), std::move(prev));
        auto processedBlock = this->_algo->encrypt(std::move(xored));
        prev = processedBlock;

        std::ranges::copy(processedBlock,
                          res.begin() + i * this->_algo->_blockSize);
      }
    } else {
      std::vector<std::future<std::vector<std::byte>>> futures;
      futures.reserve(blockCnt);

      for (std::size_t i = 0; i < blockCnt; i++) {
        std::vector block(in.begin() + i * this->_algo->_blockSize,
                          in.begin() + (i + 1) * this->_algo->_blockSize);

        std::vector<std::byte> prevBlock;

        if (i == 0) {
          prevBlock = _init_vec.value();
        } else {
          auto prevStart = in.begin() + (i - 1) * this->_algo->_blockSize;
          prevBlock =
              std::vector(prevStart, this->_algo->_blockSize + prevStart);
        }

        futures.emplace_back(std::async(
            std::launch::async, [this, block = std::move(block),
                                 prevBlock = std::move(prevBlock)]() mutable {
              auto processedBlock = this->_algo->decrypt(block);

              if (processedBlock.size() != prevBlock.size()) {
                throw std::runtime_error(
                    "блоки должны быть одного размера после дешифрования");
              }

              return xorSpan(std::move(processedBlock), prevBlock);
            }));
      }

      for (std::size_t i = 0; i < blockCnt; i++) {
        auto processedBlock = futures[i].get();
        std::ranges::copy(processedBlock,
                          res.begin() + i * this->_algo->_blockSize);
      }
    }

    return res;
  }
  [[nodiscard]] std::vector<std::byte> _processPCBC(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());
    return res;
  }
  [[nodiscard]] std::vector<std::byte> _processCFB(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());
    return res;
  }

  [[nodiscard]] std::vector<std::byte> _processOFB(
      const ACTION_MODE mode, const std::vector<std::byte>& in,
      const std::size_t blockCnt) {
    // (void)mode;

    if (in.size() != blockCnt * this->_algo->_blockSize) {
      throw std::invalid_argument("размер блока не подходит для алгоритма");
    }
    if (!_init_vec.has_value()) {
      throw std::runtime_error("IV пуст");
    }

    if (in.size() % this->_algo->_blockSize != 0) {
      throw std::runtime_error("неправильный размер");
    }
// TODO: ТУТ ВСЁ СДЕЛАТЬ
    std::vector<std::byte> res(in.size());
    return res;
  }

  [[nodiscard]] std::vector<std::byte> _processCTR(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());
    return res;
  }
  [[nodiscard]] std::vector<std::byte> _processRandomDelta(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());
    return res;
  }

  [[nodiscard]] std::future<std::vector<std::byte>> _processBlock(
      ACTION_MODE mode, std::vector<std::byte> in) {
    if (_algo == nullptr) {
      throw std::runtime_error("пустой алго");
    }
    return std::async(
        std::launch::async, [mode, in = std::move(in), this]() mutable {
          // const bool needsPadding = _encMode == encryptionMode::ECB ||
          //                           _encMode == encryptionMode::CBC ||
          //                           _encMode == encryptionMode::PCBC;
          constexpr bool needsPadding = true;
          std::vector<std::byte> processed;
          const std::vector<std::byte>& dataToProcess =
              (mode == ACTION_MODE::encrypt && needsPadding)
                  ? std::move(_doPadding(in))
                  : in;

          const std::size_t blockCnt =
              dataToProcess.size() / this->_algo->_blockSize;

          ACTION_MODE mod;
          if (mode == ACTION_MODE::encrUpad) {
            mod = ACTION_MODE::encrypt;
          } else if (mode == ACTION_MODE::decrUnpad) {
            mod = ACTION_MODE::decrypt;
          } else {
            mod = mode;
          }

          switch (_encMode) {
            case encryptionMode::ECB:
              processed = std::move(_processECB(mod, dataToProcess, blockCnt));
              break;
            case encryptionMode::CBC:
              processed = _processCBC(mod, dataToProcess, blockCnt);
              break;
            case encryptionMode::PCBC:
              processed = _processPCBC(mod, dataToProcess, blockCnt);
              break;
            case encryptionMode::CFB:
              processed = _processCFB(mod, dataToProcess, blockCnt);
              break;
            case encryptionMode::OFB:
              processed = std::move(_processOFB(mod, dataToProcess, blockCnt));
              break;
            case encryptionMode::CTR:
              processed = _processCTR(mod, dataToProcess, blockCnt);
              break;
            case encryptionMode::RandomDelta:
              processed = _processRandomDelta(mod, dataToProcess, blockCnt);
              break;
            default:
              throw std::runtime_error("ошибочка при обработке блока");
          }

          if (mode == ACTION_MODE::decrypt && needsPadding) {
            return _doUnpadding(processed);
          }

          return processed;
        });
  }

  [[nodiscard]] constexpr std::vector<std::byte> _doPadding(
      const std::vector<std::byte>& in) const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    uint8_t forAdd =
        this->_algo->_blockSize - in.size() % this->_algo->_blockSize;
    if (forAdd == 0) {
      forAdd = this->_algo->_blockSize;
    }

    std::vector res(in.size() + forAdd, static_cast<std::byte>(0));
    std::ranges::copy(in, res.begin());

    switch (_padMode) {
      case paddingMode::Zeros: {
        // ВСЁ ЗАПОЛНЯЕТСЯ НУЛЯМИ
      } break;
      case paddingMode::AnsiX923: {
        // ВСЕ НУЛИ, КРОМЕ ПОСЛЕДНЕГО - ТАМ ЧИСЛО ДОБАВЛЕННЫХ БАЙТ
        // res.back() = static_cast<std::byte>(forAdd);
        res[res.size() - 1] = static_cast<std::byte>(forAdd);
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
        // res.back() = static_cast<std::byte>(forAdd);
        res[res.size() - 1] = static_cast<std::byte>(forAdd);
      } break;
      default:
        throw std::logic_error("нет такого режима набивки");
    }

    return res;
  }

  [[nodiscard]] constexpr std::vector<std::byte> _doUnpadding(
      const std::vector<std::byte>& in) const {
    if (in.empty()) return {};

    const auto wasAdded = static_cast<uint8_t>(in.back());

    // if (wasAdded == 0 || wasAdded > in.size() ||
    //     wasAdded > this->_algo->_blockSize) {
    //   throw std::runtime_error("ошибка в анпаддинге");
    // }

    std::vector<std::byte> res;

    switch (_padMode) {
      case paddingMode::Zeros: {
        const auto it =
            std::find_if(in.rbegin(), in.rend(),
                         [](const std::byte b) { return b != std::byte{0}; });
        res = std::move(std::vector(in.begin(), it.base()));
      } break;

      case paddingMode::AnsiX923: {
        for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
          if (in[i] != static_cast<std::byte>(0)) {
            throw std::runtime_error("в AnsiX923 должны быть нули байты");
          }
        }
        res = std::move(std::vector(in.begin(), in.end() - wasAdded));
      } break;

      case paddingMode::PKCS7: {
        // for (size_t i = in.size() - wasAdded; i < in.size() + 1; ++i) {
        //   if (in[i] != static_cast<std::byte>(wasAdded)) {
        //     throw std::runtime_error("в PKCS7 должны быть одинаковые байты");
        //   }
        // }
        res = std::move(std::vector(in.begin(), in.end() - wasAdded));
      } break;

      case paddingMode::ISO10126: {
        res = std::move(std::vector(in.begin(), in.end() - wasAdded));
      } break;

      default:
        throw std::logic_error("нет такого режима набивки");
    }

    return res;
  }

 protected:
  std::vector<std::byte> _encryptionKey;
  encryptionMode _encMode;
  paddingMode _padMode;
  mutable std::optional<std::vector<std::byte>> _init_vec;
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
    _roundKeys = std::move(_algo->getRoundKeys());
    if (_roundKeys.empty()) {
      _algo->setRoundKeys(_encryptionKey);
      _roundKeys = std::move(_algo->getRoundKeys());
    }
  }

  constexpr void encrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) {
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
    dest = std::move(_processBlock(ACTION_MODE::encrypt, in).get());
  }

  // constexpr void encrypt(std::vector<std::byte>& dest,
  //                        std::span<std::byte> in) const {
  //   std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
  //   vec.assign(in.begin(), in.end());
  //   this->encrypt(dest, vec);
  // }

  constexpr void decrypt(std::vector<std::byte>& dest,
                         const std::vector<std::byte>& in) {
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
    dest = std::move(_processBlock(ACTION_MODE::decrypt, in).get());
  }

  // constexpr void decrypt(std::vector<std::byte>& dest,
  //                        std::span<std::byte> in) const {
  //   std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
  //   vec.assign(in.begin(), in.end());
  //   this->decrypt(dest, vec);
  // }

  constexpr void encrypt(const std::string& destPath,
                         const std::string& inPath) {
    _processFile(ACTION_MODE::encrypt, inPath, destPath);
  }

  constexpr void decrypt(const std::string& destPath,
                         const std::string& inPath) {
    _processFile(ACTION_MODE::decrypt, inPath, destPath);
  }
};
}  // namespace meow::cypher::symm
