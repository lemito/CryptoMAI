#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

import math.GaloisFieldPoly;
import <array>;

TEST(GF, Add) {
  const meow::math::GaloisFieldPoly::GaloisFieldPoly a(static_cast<std::byte>(0x57));
  const meow::math::GaloisFieldPoly::GaloisFieldPoly b(static_cast<std::byte>(0x83));
  const meow::math::GaloisFieldPoly::GaloisFieldPoly exp(
      static_cast<std::byte>(0xd4));
  ASSERT_EQ(a + b, exp);
  std::cout << exp << std::endl;
}

TEST(GF, Multiply) {
  const meow::math::GaloisFieldPoly::GaloisFieldPoly a(static_cast<std::byte>(0x57));
  const meow::math::GaloisFieldPoly::GaloisFieldPoly b(static_cast<std::byte>(0x83));
  const meow::math::GaloisFieldPoly::GaloisFieldPoly exp(
      static_cast<std::byte>(0xc1));
  const auto meow = a * b;
  ASSERT_EQ(meow, exp);
  std::cout << exp << std::endl;
}

TEST(GF, allIrreducibleFor8) {
  const auto res =
      meow::math::GaloisFieldPoly::GaloisFieldPoly::allIrreducibleFor8();
  ASSERT_EQ(res.size(), 30);
}

TEST(GF, decomposition) {
  const auto res =
      meow::math::GaloisFieldPoly::GaloisFieldPoly::decomposition(0xabc);
  std::cout << "============\n";
  for (auto& elem : res) {
    std::cout << elem << " ";
  }
  std::cout << std::endl;
}

TEST(GF, decomposition0) {
  const auto res =
      meow::math::GaloisFieldPoly::GaloisFieldPoly::decomposition(0x11B);
  const std::vector<uint32_t> exp{0x11B};  // туточки неприводимый
  ASSERT_EQ(res, exp);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}