#pragma once

#include <future>
#include <stdexcept>
#include <utility>

#include "math/primary/PrimaryTests.hpp"
#include "utils_math.h"

namespace meow::cypher {
class DiffieHelmanParams final {
  BI P;
  BI g;

 public:
  explicit DiffieHelmanParams(const size_t bitLength = 1024,
                              const double probability = 0.98) {
    generateParams(bitLength, probability);
  }

  constexpr DiffieHelmanParams(BI prime, BI generator)
      : P(std::move(prime)), g(std::move(generator)) {}

  void generateParams(const size_t bitLength, const double probability) {
    P = generateSafePrimeAsync(bitLength, probability);
    findGenerator();
  }

  [[nodiscard]] constexpr auto getModulus() const -> BI { return P; }
  [[nodiscard]] constexpr auto getGenerator() const -> BI { return g; }

 private:
  static auto generatePrimeNumber(const size_t bitLength,
                                  const double probability,
                                  const math::primary::MillerRabinTest& test,
                                  const std::atomic<bool>& found) -> BI {
    const BI min_val = BI(1) << (bitLength - 1);
    const BI max_val = (BI(1) << bitLength) - 1;

    while (!found) {
      BI number = meow::math::_genRandNumber<
          boost::random::uniform_int_distribution<BI>>(min_val, max_val);

      if (test.isPrimary(number, probability)) {
        return number;
      }
    }
    return {0};
  }

  static auto generateSafePrimeAsync(const size_t bitLength,
                                     const double probability) -> BI {
    const math::primary::MillerRabinTest primaryTest{};
    const unsigned num_threads = std::thread::hardware_concurrency();

    std::vector<std::future<BI>> futures;
    std::atomic found(false);

    futures.reserve(num_threads);
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

                         if (found) {
                           return {0};
                         }

                         if (BI P_candidate = q * 2 + 1;
                             primaryTest.isPrimary(P_candidate, probability)) {
                           if (!found.exchange(true)) {
                             return P_candidate;
                           }
                         }
                       }
                       return {0};
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

  static auto generateSafePrimeOptimized(const size_t bitLength,
                                         const double probability) -> BI {
    const math::primary::MillerRabinTest primaryTest{};
    const unsigned num_threads = std::thread::hardware_concurrency();

    std::vector<std::future<BI>> futures;
    std::atomic found(false);

    for (unsigned i = 0; i < num_threads; ++i) {
      constexpr size_t batch_size = 100;
      futures.push_back(std::async(
          std::launch::async,
          [bitLength, probability, &primaryTest, &found]() -> BI {
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

              for (const BI& q : candidates) {
                if (found) {
                  break;
                }

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
            return {0};
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
    findGeneratorDeterministic(q);
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
  BI publicKey;

  const DiffieHelmanParams _params;

 public:
  BI secret;

  constexpr explicit DiffieHelman(DiffieHelmanParams params)
      : _params(std::move(params)) {
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

  [[nodiscard]] constexpr auto getPublicKey() const -> BI { return publicKey; }

  [[nodiscard]] constexpr auto calcSharedSecret(const BI& otherPublicKey) const
      -> BI {
    if (otherPublicKey <= 1 ||
        otherPublicKey >= this->_params.getModulus() - 1) {
      throw std::invalid_argument("Public key must be in (1, P-1)");
    }
    return math::modPow(otherPublicKey, this->secret,
                        this->_params.getModulus());
  }
};
}  // namespace meow::cypher