/**
 * TODO: тут будет плохой RSA неустойчивый к атаке Виннера
 */

module;

#include "utils_math.h"

export module cypher.BadRSA;

import cypher.RSA;
import cypher.RSA.WiennerAttack;
import math;

export namespace meow::cypher::RSA::BadRSA {

class BadRSAService final : public RSAService,
                            public attack::WiennerAttackService {
 public:
  ~BadRSAService() override = default;
  BadRSAService(const KeyGen::PrimaryTests test, const double probability,
                const size_t bitLength)
      : RSAService(test, probability, bitLength, true) {
    // if (math::pow(private_key_.decrypt_word, 4) >= private_key_.N / 81) {
    //   std::cout << private_key_.decrypt_word << std::endl;
    //   throw std::runtime_error("норм ключи. такое не взломать");
    // }
  }
};
};  // namespace meow::cypher::RSA::BadRSA