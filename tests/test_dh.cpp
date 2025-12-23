#include <gtest/gtest.h>

#include "utils_math.h"

import DiffieHelman;

TEST(DH, Sample) {
  const meow::cypher::DiffieHelmanParams params(512, 0.95);

  const meow::cypher::DiffieHelman dhA(params);
  const meow::cypher::DiffieHelman dhB(params);

  const auto keyA = dhA.calcSharedSecret(dhB.getPublicKey());
  const auto keyB = dhB.calcSharedSecret(dhA.getPublicKey());

  ASSERT_EQ(keyA, keyB);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}