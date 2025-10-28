#include <gtest/gtest.h>
#include <stddef.h>


import math.GaloisFieldPoly;
import <array>;

TEST(GF, Add) {
  const auto a(static_cast<std::byte>(0x57));
  const auto b(static_cast<std::byte>(0x83));
  constexpr auto exp(static_cast<std::byte>(0xd4));
  constexpr auto res = meow::math::GaloisFieldPoly::plus(a, b);
  ASSERT_EQ(res, exp);
}

TEST(GF, Multiply) {
  constexpr auto a(static_cast<std::byte>(0x57));
  constexpr auto b(static_cast<std::byte>(0x83));
  constexpr auto exp(static_cast<std::byte>(0xc1));
  const auto meow = meow::math::GaloisFieldPoly::mult(
      a, b, meow::math::GaloisFieldPoly::MOD_byte);
  ASSERT_EQ(meow, exp);
  // std::cout << exp << std::endl;
}

TEST(GF, allIrreducibleFor8) {
  const auto res = meow::math::GaloisFieldPoly::allIrreducibleFor8();
  ASSERT_EQ(res.size(), 30);
}

TEST(GF, inv) {
  const auto res = meow::math::GaloisFieldPoly::invElem(
      static_cast<std::byte>(0xD2), meow::math::GaloisFieldPoly::MOD_byte);
  ASSERT_EQ(res, static_cast<std::byte>(0xAE));
}

TEST(GF, decomposition) {
  const auto res = meow::math::GaloisFieldPoly::decomposition(0xabc);
  std::cout << "============\n";
  for (auto& elem : res) {
    std::cout << elem << " ";
  }
  std::cout << std::endl;
}

TEST(GF, decomposition0) {
  const auto res = meow::math::GaloisFieldPoly::decomposition(0x11B);
  const std::vector<uint32_t> exp{0x11B};  // туточки неприводимый
  ASSERT_EQ(res, exp);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}