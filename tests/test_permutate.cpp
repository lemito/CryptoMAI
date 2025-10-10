#include <gtest/gtest.h>

#include "utils_math.h"
import cypher.permutate;

TEST(Permutate, Simple) {
  const std::vector input = {static_cast<std::byte>(0b10110011)};
  const std::vector<int64_t> permutation = {2, 0, 1, 3, 6, 4, 5, 7};

  const auto res = meow::cypher::premutate::permutation(
      input, permutation, meow::cypher::premutate::bitIndexingRule::LSB_to_MSB,
      0);
  ASSERT_TRUE(res[0] == static_cast<std::byte>(0b11001101));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}