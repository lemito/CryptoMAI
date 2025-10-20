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
  static constexpr size_t BATCH_SIZE = 64 * 1024 * 1024;

 private:
  enum class ACTION_MODE : int8_t { encrypt, decrypt };
  void _processFile(const ACTION_MODE& mode, const std::string& inPath,
                  const std::string& destPath) const {
    std::ifstream i_file(inPath, std::ios::binary);
    if (!i_file) {
      throw std::runtime_error("не удалось открыть входной файл");
    }
    std::ofstream o_file(destPath, std::ios::binary | std::ios::trunc);
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

      if (mode == ACTION_MODE::encrypt) {
        encrypt(write_buf, std::vector(buffer.begin(), buffer.begin() + read));
      } else {
        decrypt(write_buf, std::vector(buffer.begin(), buffer.begin() + read));
      }

      o_file.write(reinterpret_cast<const char*>(write_buf.data()), write_buf.size());
    }
  }

  // void _processFile(const ACTION_MODE& mode, const std::string& inPath,
  //                   const std::string& destPath) const {
  //   std::ifstream i_file(inPath, std::ios::binary);
  //   if (!i_file) {
  //     throw std::runtime_error("не удалось открыть входной файл");
  //   }
  //   std::ofstream o_file(destPath, std::ios::binary | std::ios::trunc);
  //   if (!o_file) {
  //     throw std::runtime_error("не удалось открыть выходной файл");
  //   }
  //
  //   std::vector<std::byte> read_buf(BATCH_SIZE);
  //   std::vector<std::byte> process_buf;
  //   std::vector<std::byte> output_buf;
  //
  //   while (i_file) {
  //     i_file.read(reinterpret_cast<char*>(read_buf.data()), read_buf.size());
  //     std::streamsize bytes_read = i_file.gcount();
  //
  //     if (bytes_read == 0) {
  //       break;
  //     }
  //
  //     process_buf.assign(read_buf.begin(), read_buf.begin() + bytes_read);
  //     output_buf.resize(bytes_read);
  //
  //     if (mode == ACTION_MODE::encrypt) {
  //       encrypt(output_buf, process_buf);
  //     } else {
  //       decrypt(output_buf, process_buf);
  //     }
  //
  //     o_file.write(reinterpret_cast<const char*>(output_buf.data()),
  //                  output_buf.size());
  //   }
  // }

  // while (true) {
  //   i_file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
  //   std::streamsize bytes_read = i_file.gcount();
  //
  //   if (bytes_read == 0) {
  //     if (!i_file.eof()) {
  //       if (i_file.fail()) {
  //         throw std::runtime_error("ошибка чтения из файла: " + inPath);
  //       }
  //     } else {
  //       break;
  //     }
  //   }
  //
  //   auto input_span =
  //       std::span(buffer.data(), static_cast<size_t>(bytes_read));
  //
  //   write_buffer.clear();
  //
  //   if (mode == ACTION_MODE::encrypt) {
  //     encrypt(write_buffer, {input_span.begin(), input_span.end()});
  //   } else {
  //     decrypt(write_buffer, {input_span.begin(), input_span.end()});
  //   }
  //
  //   o_file.write(reinterpret_cast<const char*>(write_buffer.data()),
  //                write_buffer.size());
  //
  //   if (!o_file) {
  //     throw std::runtime_error("ошибка записи в файл: " + destPath);
  //   }
  //
  //   o_file.flush();
  //   if (!o_file) {
  //     throw std::runtime_error("ошибка сброса буфера записи: " + destPath);
  //   }
  // }
  //
  // o_file.flush();
  // }

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
          std::async(std::launch::async, [this, &in, &res, i, mode]() {
            const size_t off = i * this->_algo->_blockSize;
            const std::vector block(in.begin() + off,
                                    in.begin() + off + this->_algo->_blockSize);

            std::vector<std::byte> processed_block;
            if (mode == ACTION_MODE::encrypt) {
              processed_block = this->_algo->encrypt(block);
            } else {
              processed_block = this->_algo->decrypt(block);
            }

            std::ranges::copy(processed_block, res.begin() + off);
          }));
    }

    for (auto& f : futures) {
      f.get();
    }

    return res;
  }
  [[nodiscard]] std::vector<std::byte> _processCBC(
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
    std::vector<std::byte> res(in.size());
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
      ACTION_MODE mode, const std::vector<std::byte>& in,
      std::size_t blockCnt) const {
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
      const ACTION_MODE mode, std::vector<std::byte> in) const {
    return std::async(std::launch::deferred, [mode, in = std::move(in),
                                              this]() mutable {
      const bool needsPadding = _encMode == encryptionMode::ECB ||
                                _encMode == encryptionMode::CBC ||
                                _encMode == encryptionMode::PCBC;

      std::vector<std::byte> processed;
      const std::vector<std::byte>& dataToProcess =
          (mode == ACTION_MODE::encrypt && needsPadding) ? _doPadding(in) : in;

      const std::size_t blockCnt =
          dataToProcess.size() / this->_algo->_blockSize;

      switch (_encMode) {
        case encryptionMode::ECB:
          processed = _processECB(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::CBC:
          processed = _processCBC(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::PCBC:
          processed = _processPCBC(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::CFB:
          processed = _processCFB(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::OFB:
          processed = _processOFB(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::CTR:
          processed = _processCTR(mode, dataToProcess, blockCnt);
          break;
        case encryptionMode::RandomDelta:
          processed = _processRandomDelta(mode, dataToProcess, blockCnt);
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
        res = std::vector(in.begin(), it.base());
      } break;

      case paddingMode::AnsiX923: {
        for (size_t i = in.size() - wasAdded; i < in.size() - 1; ++i) {
          if (in[i] != static_cast<std::byte>(0)) {
            throw std::runtime_error("в AnsiX923 должны быть нули байты");
          }
        }
        res = std::vector(in.begin(), in.end() - wasAdded);
      } break;

      case paddingMode::PKCS7: {
        // for (size_t i = in.size() - wasAdded; i < in.size() + 1; ++i) {
        //   if (in[i] != static_cast<std::byte>(wasAdded)) {
        //     throw std::runtime_error("в PKCS7 должны быть одинаковые байты");
        //   }
        // }
        res = std::vector(in.begin(), in.end() - wasAdded);
      } break;

      case paddingMode::ISO10126: {
        res = std::vector(in.begin(), in.end() - wasAdded);
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
    _roundKeys = _algo->getRoundKeys();
    if (_roundKeys.empty()) {
      _algo->setRoundKeys(_encryptionKey);
      _roundKeys = _algo->getRoundKeys();
    }
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

  // constexpr void encrypt(std::vector<std::byte>& dest,
  //                        std::span<std::byte> in) const {
  //   std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
  //   vec.assign(in.begin(), in.end());
  //   this->encrypt(dest, vec);
  // }

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

  // constexpr void decrypt(std::vector<std::byte>& dest,
  //                        std::span<std::byte> in) const {
  //   std::vector<std::byte> vec;  // вынужденная копия в угоду span-а
  //   vec.assign(in.begin(), in.end());
  //   this->decrypt(dest, vec);
  // }

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
