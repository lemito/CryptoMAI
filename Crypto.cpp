#include "Crypto.h"

import cypher;
import PrimaryTests;
import math;

using namespace std;

int main() {
  meow::cypher::test_module();
  auto [d, x, y] = meow::math::eGCD(240, 46);
  const meow::math::primary::FermatTest f;
  const meow::math::primary::MillerRabinTest mr;
  std::cout << f.roundCnt(0.9998) << std::endl;
  std::cout << mr.roundCnt(0.9998) << std::endl;
  std::cout << d << " " << x << ' ' << y << std::endl;
  std::cout << "GCD(48, 18) = " << meow::math::GCD(48, 18) << std::endl;
  std::cout << "GCD(17, 13) = " << meow::math::GCD(17, 13) << std::endl;
  std::cout << "GCD(0, 5) = " << meow::math::GCD(0, 5) << std::endl;
  std::cout << meow::math::LejandreSymbol(12345, 331) << std::endl;
  std::cout << meow::math::JacobiSymbol(219, 383) << std::endl;
  return 0;
}
