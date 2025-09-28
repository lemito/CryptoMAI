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
  std::cout << meow::math::LejandreSymbol(12345, 331) << std::endl;
  return 0;
}
