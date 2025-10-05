/**
 * TODO: тут будет плохой RSA неустойчивый к атаке Виннера
 */

module;

#include "utils_math.h"

export module cypher.BadRSA;

import cypher.RSA;
import cypher.RSA.WiennerAttack;

export namespace meow::cypher::RSA::BadRSA {

class BadRSAService final : public RSAService,
                            public attack::WiennerAttackService {
 public:
  ~BadRSAService() override = default;
  BadRSAService(const KeyGen::PrimaryTests test, const double probability,
                const size_t bitLength)
      : RSAService(test, probability, bitLength, true) {}
};
};  // namespace meow::cypher::RSA::BadRSA