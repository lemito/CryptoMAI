module;
#include <future>
#include <stdexcept>

#include "utils_math.h"

export module DiffieHelman;

import math;
import math.PrimaryTests;

export namespace meow::cypher {
class DiffieHelmanParams final {
  BI P;
  BI g;

 public:
  explicit DiffieHelmanParams(const size_t bitLength = 1024,
                              const double probability = 0.98) {
    generateParams(bitLength, probability);
  }

  constexpr DiffieHelmanParams(const BI& prime, const BI& generator)
      : P(prime), g(generator) {}

  void generateParams(const size_t bitLength, const double probability) {
    P = generateSafePrimeAsync(bitLength, probability);
    findGenerator();
  }

  [[nodiscard]] constexpr BI getModulus() const { return P; }
  [[nodiscard]] constexpr BI getGenerator() const { return g; }

 private:
  static BI generatePrimeNumber(const size_t bitLength,
                                const double probability,
                                const math::primary::MillerRabinTest& test,
                                const std::atomic<bool>& found) {
    const BI min_val = BI(1) << (bitLength - 1);
    const BI max_val = (BI(1) << bitLength) - 1;

    while (!found) {
      BI number = meow::math::_genRandNumber<
          boost::random::uniform_int_distribution<BI>>(min_val, max_val);

      if (test.isPrimary(number, probability)) {
        return number;
      }
    }
    return BI(0);
  }

  static BI generateSafePrimeAsync(const size_t bitLength,
                                   const double probability) {
    const math::primary::MillerRabinTest primaryTest{};
    const unsigned num_threads = std::thread::hardware_concurrency();

    std::vector<std::future<BI>> futures;
    std::atomic found(false);

    for (unsigned i = 0; i < num_threads; ++i) {
      futures.push_back(
          std::async(std::launch::async,
                     [bitLength, probability, &primaryTest, &found]() -> BI {
                       while (!found) {
                         auto q = BI(0);
                         while (!found && q == BI(0)) {
                           q = generatePrimeNumber(bitLength - 1, probability,
                                                   primaryTest, found);
                         }

                         if (found) return BI(0);

                         if (BI P_candidate = q * 2 + 1;
                             primaryTest.isPrimary(P_candidate, probability)) {
                           if (!found.exchange(true)) {
                             return P_candidate;
                           }
                         }
                       }
                       return BI(0);
                     }));
    }

    for (auto& future : futures) {
      if (BI result = future.get(); result != BI(0)) {
        found = true;
        return result;
      }
    }

    throw std::runtime_error("Failed to generate safe prime");
  }

  static BI generateSafePrimeOptimized(const size_t bitLength,
                                       const double probability) {
    const math::primary::MillerRabinTest primaryTest{};
    const unsigned num_threads = std::thread::hardware_concurrency();

    std::vector<std::future<BI>> futures;
    std::atomic found(false);

    for (unsigned i = 0; i < num_threads; ++i) {
      constexpr size_t batch_size = 100;
      futures.push_back(std::async(
          std::launch::async,
          [bitLength, probability, &primaryTest, &found, batch_size]() -> BI {
            const BI min_val = BI(1) << (bitLength - 2);
            const BI max_val = (BI(1) << (bitLength - 1)) - 1;

            while (!found) {
              std::vector<BI> candidates;
              for (size_t j = 0; j < batch_size && !found; ++j) {
                candidates.push_back(
                    meow::math::_genRandNumber<
                        boost::random::uniform_int_distribution<BI>>(min_val,
                                                                     max_val));
              }

              for (BI q : candidates) {
                if (found) break;

                if (primaryTest.isPrimary(q, probability)) {
                  if (BI P_candidate = q * 2 + 1;
                      primaryTest.isPrimary(P_candidate, probability)) {
                    if (!found.exchange(true)) {
                      return P_candidate;
                    }
                  }
                }
              }
            }
            return BI(0);
          }));
    }

    for (auto& future : futures) {
      if (BI result = future.get(); result != BI(0)) {
        found = true;
        return result;
      }
    }

    throw std::runtime_error("Failed to generate safe prime");
  }

  constexpr void findGenerator() {
    const BI q = (P - 1) / 2;

    static constexpr std::array FAST_CANDIDATES = {
        2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,
        43,  47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
        173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
        241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
        317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
        401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
        479, 487, 491, 499, 503, 509, 521, 523, 541};

    for (int prime_candidate : FAST_CANDIDATES) {
      BI candidate(prime_candidate);
      if (candidate >= P) break;
      // g^q mod P != 1 => g - генератор
      if (math::modPow(candidate, q, P) != 1) {
        g = candidate;
        return;
      }
    }

    // если не прокнуло из готовой таблицы
    if (tryRandomSearch(q)) {
      return;
    }

    // если и рандом не прокнул
    findGeneratorDeterministic(q);
  }

  bool tryRandomSearch(const BI& q) {
    // P = 2q+1
    // phi(P) = P - 1 = 2q => phi(2q) = phi(2)*phi(q)=1*(q-1)=q-1 => на прямой
    // может быть P-3 потенциальных генератора вероятность того, что мы его
    // нашли: p = (q - 1) / (P - 3) = (q - 1) / (2q - 2) = 1/2
    constexpr size_t MAX_ATTEMPTS = 500;

    for (size_t i = 0; i < MAX_ATTEMPTS; ++i) {
      if (const BI candidate =
              math::_genRandNumber<boost::random::uniform_int_distribution<BI>>(
                  2, P - 2);
          math::modPow(candidate, q, P) != 1) {
        this->g = candidate;
        return true;
      }
    }
    return false;
  }

  void findGeneratorDeterministic(const BI& q) {
    BI candidate = 2;

    while (candidate < P - 1) {
      if (math::modPow(candidate, q, P) == P - 1) {
        g = candidate;
        return;
      }
      candidate += (candidate % 2 == 0) ? 1 : 2;
    }

    throw std::runtime_error("MEOW :(");
  }
};

class DiffieHelman final {
  BI secret;
  BI publicKey;
  const DiffieHelmanParams _params;

 public:
  constexpr explicit DiffieHelman(const DiffieHelmanParams& params)
      : _params(params) {
    genKeys();
  }

  constexpr DiffieHelman(const BI& prime, const BI& generator)
      : _params(prime, generator) {
    genKeys();
  }

  constexpr void genKeys() {
    const BI min_val = 2;
    const BI max_val = this->_params.getModulus() - 2;

    this->secret =
        math::_genRandNumber<boost::random::uniform_int_distribution<BI>>(
            min_val, max_val);

    this->publicKey =
        math::modPow(_params.getGenerator(), secret, _params.getModulus());
  }

  [[nodiscard]] constexpr BI getPublicKey() const { return publicKey; }

  [[nodiscard]] constexpr BI calcSharedSecret(const BI& otherPublicKey) const {
    if (otherPublicKey <= 1 ||
        otherPublicKey >= this->_params.getModulus() - 1) {
      throw std::invalid_argument("Public key must be in (1, P-1)");
    }
    return math::modPow(otherPublicKey, this->secret,
                        this->_params.getModulus());
  }
};
}  // namespace meow::cypher