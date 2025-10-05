module;
#include <memory>
#include <stdexcept>
#include <utility>

#include "utils_math.h"

export module cypher.RSA;

import math;
import math.PrimaryTests;
import cypher;

export namespace meow::cypher::RSA {
class RSAService {
  static constexpr BI EulerFuncN(const BI &p, const BI &q) {
    return (p - 1) * (q - 1);
  }

 protected:
  struct PublicKey {
    BI encrypt_word{};
    BI N{};
    PublicKey(BI e, BI n) : encrypt_word(std::move(e)), N(std::move(n)) {}
  };
  struct PrivateKey {
    BI decrypt_word{};
    BI N{};
    PrivateKey(BI d, BI n) : decrypt_word(std::move(d)), N(std::move(n)) {}
  };
  PrivateKey private_key_;

 public:
  PublicKey public_key_;
  class KeyGen final {
    std::shared_ptr<math::primary::AbstractPrimaryTest> _primaryTest{};
    double _probability = 0.89;
    size_t _bitLength = 1024;
    boost::random::mt19937 _gen{static_cast<unsigned>(std::time(nullptr))};

    constexpr BI genRandNumber() {
      const BI min_val = BI(1) << (_bitLength - 1);
      const BI max_val = (BI(1) << _bitLength) - 1;

      const boost::random::uniform_int_distribution<BI> dist(min_val, max_val);
      return dist(_gen);
    }

    constexpr BI genPrimeNumber() {
      BI number;
      do {
        number = genRandNumber();
      } while (!_primaryTest->isPrimary(number, _probability));
      return number;
    }

    constexpr std::tuple<BI, BI, BI> _setExponents() {
      BI e;
      BI q;
      const BI p = genPrimeNumber();
      do {
        q = genPrimeNumber();
      } while (!good4FermatAttack(p, q));
      BI N = p * q;
      const auto phi = EulerFuncN(p, q);

      // 49081 -- просто рандомное простое число из https://oeis.org/A004023
      const boost::random::uniform_int_distribution<BI> dist(49081, phi);

      do {
        e = dist(_gen);
      } while (math::GCD(e, phi) != 1);

      // d*e === 1 mod phi==> найти надо d eGCD ax+by==gcd => x*(x^-1)+0*b==1
      const auto [gcd, x, y] = math::eGCD(e, phi);
      BI d = x;

      return {e, d, N};
    }

   protected:
    constexpr std::pair<PublicKey, PrivateKey> _genKeys(
        const bool needHackedByWienner = false) {
      BI e;
      BI d;
      BI N;
      if (needHackedByWienner) {
        do {
          std::tie(e, d, N) = _setExponents();
        } while (e <= 0 || d <= 0);
      } else {
        do {
          std::tie(e, d, N) = _setExponents();
        } while (!good4WiennerAttack(d, N) || e <= 0 || d <= 0);
      }

      return {PublicKey(e, N), PrivateKey(d, N)};
    }

   public:
    enum class PrimaryTests : int8_t {
      FermatTest,
      SoloveyStrassenTest,
      MillerRabinTest
    };

    KeyGen(const PrimaryTests test, const double probability,
           const size_t bitLength)
        : _probability{probability}, _bitLength{bitLength} {
      if (math::primary::doubleLess(probability, 0.5) ||
          math::primary::doubleGreaterEq(probability, 1.0)) {
        throw std::invalid_argument(
            "Вероятность должна быть в пределах [0.5;1)");
      }
      if (bitLength < 256 || (bitLength & 1) == 1) {
        throw std::invalid_argument("Слишком малый размер");
      }
      switch (test) {
        case PrimaryTests::FermatTest: {
          _primaryTest = std::make_shared<math::primary::FermatTest>();
          break;
        }
        case PrimaryTests::SoloveyStrassenTest: {
          _primaryTest = std::make_shared<math::primary::SoloveyStrassenTest>();
          break;
        }
        case PrimaryTests::MillerRabinTest: {
          _primaryTest = std::make_shared<math::primary::MillerRabinTest>();
          break;
        }
        default: {
          throw std::invalid_argument("Такого теста нет");
          break;
        }
      }
    }

    KeyGen(const KeyGen &) = delete;
    KeyGen(KeyGen &&) = delete;
    KeyGen &operator=(const KeyGen &) = delete;
    KeyGen &operator=(KeyGen &&) = delete;
    ~KeyGen() = default;

    /// проверка на восприимчивость к атаке Ферма
    [[nodiscard]] constexpr bool good4FermatAttack(const BI &p,
                                                   const BI &q) const {
      BI diff;
      if (p > q) {
        diff = p - q;
      } else {
        diff = q - p;
      }

      constexpr size_t window = 100;
      const size_t coeff = _bitLength / 2 - window;
      const BI good_diff = BI(1) << coeff;

      return diff >= good_diff;
    }
    /// проверка на восприимчивость к атаке Виннера
    static constexpr bool good4WiennerAttack(const BI &d, const BI &N) {
      // d < 1/3 * N^(1/4) === d^4 < 1/81 * N
      if (math::pow(d, 4) < N / 81) {
        // атака отработала и сломала моё милое сообщение
        return false;
      }
      return true;
    }

    constexpr std::pair<PublicKey, PrivateKey> genKeys(
        const bool needHackedByWienner = false) {
      return _genKeys(needHackedByWienner);
    }
  };

 private:
  std::shared_ptr<KeyGen> _keyGen;
  constexpr void _init(const bool get_wienner_flag) {
    !get_wienner_flag ? std::println("Безопасный сервис")
                      : std::println("НеБезопасный сервис");
    auto [x, y] = _keyGen->genKeys(get_wienner_flag);
    public_key_ = std::move(x);
    private_key_ = std::move(y);
  }

 public:
  RSAService(const KeyGen::PrimaryTests test, const double probability,
             const size_t bitLength, const bool needForWiennerAttack = false)
      : private_key_(0, 0), public_key_(0, 0) {
    if (math::primary::doubleLess(probability, 0.5) ||
        math::primary::doubleGreaterEq(probability, 1.0)) {
      throw std::invalid_argument("Вероятность должна быть в пределах [0.5;1)");
    }
    _keyGen = std::make_shared<KeyGen>(test, probability, bitLength);
    _init(needForWiennerAttack);
  }
  RSAService(const RSAService &) = delete;
  RSAService(RSAService &&) = delete;
  RSAService &operator=(const RSAService &) = delete;
  RSAService &operator=(RSAService &&) = delete;
  virtual ~RSAService() = default;

  [[nodiscard]] constexpr BI encrypt(const BI &msg) const {
    return math::modPow(msg, public_key_.encrypt_word, public_key_.N);
  }
  [[nodiscard]] constexpr BI decrypt(const BI &msg) const {
    return math::modPow(msg, private_key_.decrypt_word, private_key_.N);
  }
};
}  // namespace meow::cypher::RSA