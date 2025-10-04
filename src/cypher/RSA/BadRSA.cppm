/**
 * TODO: тут будет плохой RSA неустойчивый к атаке Виннера
 */

module;

#include "utils_math.h"

export module BadRSA;

import cypher.RSA;

namespace meow::cypher::RSA::BadRSA {
class BadRSAService : RSAService {
 public:
  BadRSAService(const KeyGen::PrimaryTests test, const double probability,
                const size_t bitLength)
      : RSAService(test, probability, bitLength) {}
};
};  // namespace meow::cypher::RSA::BadRSA