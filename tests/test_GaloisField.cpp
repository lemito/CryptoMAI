#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

import math.GaloisFieldPoly;
import <array>;

TEST(GF, Add) {
  meow::math::GaloisFieldPoly::GaloisFieldPoly a(static_cast<std::byte>(0x57));
  meow::math::GaloisFieldPoly::GaloisFieldPoly b(static_cast<std::byte>(0x83));
  meow::math::GaloisFieldPoly::GaloisFieldPoly exp(
      static_cast<std::byte>(0xd4));
  ASSERT_EQ(a + b, exp);
  std::cout << exp << std::endl;
}

TEST(GF, Multiply) {
  meow::math::GaloisFieldPoly::GaloisFieldPoly a(static_cast<std::byte>(0x57));
  meow::math::GaloisFieldPoly::GaloisFieldPoly b(static_cast<std::byte>(0x83));
  meow::math::GaloisFieldPoly::GaloisFieldPoly exp(
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

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}