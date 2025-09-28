#include "Crypto.h"

import cypher;
import PrimaryTests;
import math;

using namespace std;

int main() {
  cout << "Hello CMake." << endl;
  meow::cypher::test_module();
  auto [d, x, y] = meow::math::eGCD(240, 46);
  std::cout << d << " " << x << ' ' << y << std::endl;
  std::cout << 240 * x + 46 * y << std::endl;
  return 0;
}
