#include <gtest/gtest.h>

import cypher;
import cypher.FeistelNet;

TEST(Feistel, Simple) {
  const meow::cypher::symm::FeistelNet::FeistelNet feistelService(
      {static_cast<std::byte>('h'), static_cast<std::byte>('h')}, 16,
      std::make_shared<meow::cypher::symm::IGenRoundKey>(),
      std::make_shared<meow::cypher::symm::IEncryptionDecryption>());
  const std::vector msg = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};
  const auto pre_res = feistelService.encrypt(msg);
  const auto res = feistelService.decrypt(pre_res);
  ASSERT_EQ(res, msg);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}