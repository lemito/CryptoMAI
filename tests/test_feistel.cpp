#include <gtest/gtest.h>

import cypher.FeistelNet;

TEST(Feistel, Simple) {
  meow::cypher::symm::FeistelNet::FeistelNet feistelService(
      {static_cast<std::byte>('8')}, 16, nullptr, nullptr);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}