#include <gtest/gtest.h>

#include "utils_math.h"

import math;

TEST(GCDTest, Base) {
  EXPECT_EQ(meow::math::GCD(48, 18), 6);
  EXPECT_EQ(meow::math::GCD(17, 13), 1);
  EXPECT_EQ(meow::math::GCD(0, 5), 5);
  EXPECT_EQ(meow::math::GCD(5, 0), 5);
  EXPECT_EQ(meow::math::GCD(0, 0), 0);
}

TEST(GCDTest, BigNums) {
  EXPECT_EQ(
      meow::math::GCD(BI("12345678901234567890"), BI("98765432109876543210")),
      900000000090);
  EXPECT_EQ(meow::math::GCD(BI("123456789"), 1), 1);
}

TEST(EGCDTest, Base_eGCD) {
  auto [d, x, y] = meow::math::eGCD(240, 46);
  EXPECT_EQ(d, 2);
  EXPECT_EQ(x, -9);
  EXPECT_EQ(y, 47);
  EXPECT_EQ(240 * x + 46 * y, d);
}

TEST(EGCDTest, eGCD) {
  auto [d1, x1, y1] = meow::math::eGCD(48, 18);
  EXPECT_EQ(d1, 6);
  EXPECT_EQ(48 * x1 + 18 * y1, d1);

  auto [d2, x2, y2] = meow::math::eGCD(17, 13);
  EXPECT_EQ(d2, 1);
  EXPECT_EQ(17 * x2 + 13 * y2, d2);

  auto [d3, x3, y3] = meow::math::eGCD(0, 5);
  EXPECT_EQ(d3, 5);
  EXPECT_EQ(0 * x3 + 5 * y3, d3);
}