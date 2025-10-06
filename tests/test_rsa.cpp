#include <gtest/gtest.h>

#include "utils_math.h"
import cypher.RSA;

TEST(RSA, Simple) {
  const auto some_msg = BI("74123657855656565836662666");
  const meow::cypher::RSA::RSAService service{
      meow::cypher::RSA::RSAService::KeyGen::PrimaryTests::MillerRabinTest,
      0.98, 1024};
  const auto res = service.encrypt(some_msg);
  const auto res2 = service.decrypt(res);
  ASSERT_TRUE(some_msg == res2);
}

TEST(RSA, Simple1) {
  const auto some_msg = BI("74123657855656565836662666");
  const meow::cypher::RSA::RSAService service{
      meow::cypher::RSA::RSAService::KeyGen::PrimaryTests::MillerRabinTest,
      0.98, 2024};
  const auto res = service.encrypt(some_msg);
  const auto res2 = service.decrypt(res);
  ASSERT_TRUE(some_msg == res2);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}