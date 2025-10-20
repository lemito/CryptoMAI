#include <gtest/gtest.h>
#include <span>
#include "utils_math.h"
import cypher.utils;

TEST(Permutate, SimpleMSB2LSB) {
  const std::vector input = {static_cast<std::byte>(0b10110011)};
  std::vector<uint16_t> permutation = {2, 0, 1, 3, 6, 4, 5, 7};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::MSB2LSB, 0);
  ASSERT_EQ(res[0], static_cast<std::byte>(0b11011001));
}

TEST(Permutate, Simple1LSB2MSB) {
  const std::vector input = {std::byte{0b10110011}, std::byte{0b01101100}};
  std::vector<uint16_t> permutation = {15, 14, 13, 12, 11, 10, 9, 8,
                                       7,  6,  5,  4,  3,  2,  1, 0};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::LSB2MSB, 0);

  ASSERT_EQ(res[0], std::byte{0b00110110});
  ASSERT_EQ(res[1], std::byte{0b11001101});
}

TEST(Permutate, Simple2MSB2LSB) {
  const std::vector input = {std::byte{0b10110011}, std::byte{0b01101100}};
  std::vector<uint16_t> permutation = {2, 15, 1,  3,  6,  4, 5,  7,
                                       8, 13, 11, 10, 12, 0, 14, 9};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::MSB2LSB, 0);

  ASSERT_EQ(res[0], std::byte{0b10011001});
  ASSERT_EQ(res[1], std::byte{0b01011101});
}

TEST(Permutate, Simple1MSB2LSB) {
  const std::vector input = {std::byte{0b10110011}, std::byte{0b01101100}};
  std::vector<uint16_t> permutation = {15, 14, 13, 12, 11, 10, 9, 8,
                                       7,  6,  5,  4,  3,  2,  1, 0};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::MSB2LSB, 0);

  ASSERT_EQ(res[0], std::byte{0b00110110});
  ASSERT_EQ(res[1], std::byte{0b11001101});
}

TEST(Permutate, SimpleLSB2MSB) {
  const std::vector input = {static_cast<std::byte>(0b10110011)};
  std::vector<uint16_t> permutation = {2, 0, 1, 3, 6, 4, 5, 7};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::LSB2MSB, 0);
  ASSERT_EQ(res[0], static_cast<std::byte>(0b11100110));
}

TEST(Permutate, Simple2LSB2MSB) {
  const std::vector input = {std::byte{0b10110011}, std::byte{0b01101100}};
  std::vector<uint16_t> permutation = {2, 15, 1,  3,  6,  4, 5,  7,
                                       8, 13, 11, 10, 12, 0, 14, 9};

  const auto res = meow::cypher::permutate::permutation(
      input, permutation, meow::cypher::permutate::bitIndexingRule::LSB2MSB, 0);

  ASSERT_EQ(res[0], std::byte{0b11100100});
  ASSERT_EQ(res[1], std::byte{0b01101110});
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}