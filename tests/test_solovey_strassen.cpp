#include <gtest/gtest.h>

#include "utils_math.h"
import math.PrimaryTests;

TEST(SoloveyStrassenTest, SmallPrimes) {
  const meow::math::primary::SoloveyStrassenTest ss;
  for (const std::vector<BI> small_primes = {3, 5, 7, 11, 13, 17, 19, 23, 29,
                                             31};
       const auto& prime : small_primes) {
    EXPECT_TRUE(ss.isPrimary(prime, 0.9998));
  }
}

TEST(SoloveyStrassenTest, SmallComposites) {
  const meow::math::primary::SoloveyStrassenTest ss;
  for (const std::vector<BI> composites = {4, 6, 8, 9, 10, 12, 14, 15, 16, 18,
                                           20, 21, 22, 24, 25};
       const auto& composite : composites) {
    EXPECT_FALSE(ss.isPrimary(composite, 0.9998));
  }
}

TEST(SoloveyStrassenTest, MediumPrimes) {
  const meow::math::primary::SoloveyStrassenTest ss;
  for (const std::vector<BI> primes = {101, 103, 107, 109, 113, 127, 131, 137,
                                       139, 149};
       const auto& prime : primes) {
    EXPECT_TRUE(ss.isPrimary(prime, 0.9998));
  }
}

TEST(SoloveyStrassenTest, MediumComposites) {
  const meow::math::primary::SoloveyStrassenTest ss;
  std::vector<BI> composites = {100, 102, 104, 105, 106,
                                108, 110, 111, 112, 114};
  for (const auto& composite : composites) {
    EXPECT_FALSE(ss.isPrimary(composite, 0.9998));
  }
}

TEST(SoloveyStrassenTest, LargePrimes) {
  const meow::math::primary::SoloveyStrassenTest ss;
  for (const BI& prime :
       {BI("8683317618811886495518194401279999999"),
        BI("263130836933693530167218012159999999"),
        BI("265252859812191058636308479999999"),
        BI("10888869450418352160768000001"), BI("900900900900990990990991")}) {
    EXPECT_TRUE(ss.isPrimary(prime, 0.9998));
  }
}

TEST(SoloveyStrassenTest, LargeComposites) {
  const meow::math::primary::SoloveyStrassenTest ss;
  std::vector<BI> composites = {BI("1001"), BI("10001"), BI("100001"),
                                BI("1000001"), BI("10000001")};
  for (const auto& composite : composites) {
    EXPECT_FALSE(ss.isPrimary(composite, 0.9998));
  }
}

TEST(SoloveyStrassenTest, EdgeCases) {
  const meow::math::primary::SoloveyStrassenTest ss;
  ASSERT_THROW(ss.isPrimary(BI(0), 0.9998), std::runtime_error);
  ASSERT_THROW(ss.isPrimary(BI(1), 0.9998), std::runtime_error);
  EXPECT_TRUE(ss.isPrimary(BI(2), 0.9998));
}

TEST(SoloveyStrassenTest, RoundCountCalculation) {
  const meow::math::primary::SoloveyStrassenTest ss;
  EXPECT_GT(ss.roundCnt(0.9998), 0);
  EXPECT_GE(ss.roundCnt(0.9999), ss.roundCnt(0.9998));
}