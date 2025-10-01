#include <gtest/gtest.h>

#include "utils_math.h"

import math;

TEST(LejandreSymbolTest, Base) {
  EXPECT_EQ(meow::math::LejandreSymbol(BI(12345), BI(331)), -1);
}

TEST(LejandreSymbolTest, EdgeCases) {
  EXPECT_EQ(meow::math::LejandreSymbol(BI(7), BI(7)), 0);
  EXPECT_EQ(meow::math::LejandreSymbol(BI(14), BI(7)), 0);

  EXPECT_EQ(meow::math::LejandreSymbol(BI(21), BI(7)), 0);
}

TEST(JacobiSymbolTest, Base) {
  EXPECT_EQ(meow::math::JacobiSymbol(BI(219), BI(383)), -1);

  EXPECT_EQ(meow::math::JacobiSymbol(BI(1), BI(7)), 1);
  EXPECT_EQ(meow::math::JacobiSymbol(BI(2), BI(15)), 1);
  EXPECT_EQ(meow::math::JacobiSymbol(BI(3), BI(15)), 0);
}

TEST(JacobiSymbolTest, CompositeModulus) {
  EXPECT_EQ(meow::math::JacobiSymbol(BI(7), BI(15)), -1);
  EXPECT_EQ(meow::math::JacobiSymbol(BI(11), BI(9)), 1);
  EXPECT_EQ(meow::math::JacobiSymbol(BI(5), BI(21)), -1);
}

TEST(JacobiSymbolTest, EdgeCasesJacobi) {
  EXPECT_EQ(meow::math::JacobiSymbol(BI(3), BI(9)), 0);
  EXPECT_EQ(meow::math::JacobiSymbol(BI(6), BI(15)), 0);

  EXPECT_EQ(meow::math::JacobiSymbol(BI(5), BI(1)), 1);

  EXPECT_EQ(meow::math::JacobiSymbol(BI(0), BI(7)), 0);
}

TEST(JacobiSymbolTest, LargeNumbers) {
  EXPECT_EQ(meow::math::JacobiSymbol(BI("123456789012345678901234567890"),
                                     BI("98765432109876543210987654321")),
            1);
}