#include <gtest/gtest.h>

#include <print>

#include "utils_math.h"
import cypher.BadRSA;
import cypher.RSA.WiennerAttack;

TEST(ContinuedFraction, Basic0) {
  const BI a = 649;
  const BI b = 200;
  const std::vector<BI> expect = {3, 4, 12, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(ContinuedFraction, Basic1) {
  const BI a = 9;
  const BI b = 4;
  const std::vector<BI> expect = {2, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(ContinuedFraction, Basic2) {
  const BI a = 4;
  const BI b = 9;
  const std::vector<BI> expect = {0, 2, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(Convergents, Basic) {
  const BI a = 15;
  const BI b = 47;
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  for (const auto conv = meow::cypher::RSA::attack::WiennerAttackService::
           ContinuedFraction::convergentsCF(res);
       auto& re : conv) {
    std::cout << re << std::endl;
  }
}

TEST(BadRSA, Simple) {
  const auto some_msg = BI("74123657855656565836662666");
  const meow::cypher::RSA::BadRSA::BadRSAService service{
      meow::cypher::RSA::BadRSA::BadRSAService::KeyGen::PrimaryTests::
          MillerRabinTest,
      0.98, 1024};
  const auto res = service.encrypt(some_msg);
  const auto res2 = service.decrypt(res);
  ASSERT_TRUE(some_msg == res2);
}

TEST(BadRSA, Hack) {
  const auto some_msg = BI("74123657855656565836662666");
  const meow::cypher::RSA::BadRSA::BadRSAService service{
      meow::cypher::RSA::BadRSA::BadRSAService::KeyGen::PrimaryTests::
          MillerRabinTest,
      0.98, 2048};
  const auto res = service.encrypt(some_msg);
  const auto res2 = service.decrypt(res);
  std::cout << "e= " << service.public_key_.encrypt_word
            << "\nN= " << service.public_key_.N << std::endl;
  const auto hackRes =
      service.hack(service.public_key_.encrypt_word, service.public_key_.N);
  std::cout << hackRes.decrypt_exp << std::endl;
  for (auto& elem : hackRes.convergents) {
    std::cout << elem << std::endl;
  }
}