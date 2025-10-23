#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

import cypher;
import cypher.DEAL;

TEST(DEAL, Simple) {
  const std::vector key = {
      static_cast<std::byte>(0xAA), static_cast<std::byte>(0xBB),
      static_cast<std::byte>(0x09), static_cast<std::byte>(0x18),
      static_cast<std::byte>(0x27), static_cast<std::byte>(0x36),
      static_cast<std::byte>(0xCC), static_cast<std::byte>(0xDD),
      static_cast<std::byte>(0xAA), static_cast<std::byte>(0xBB),
      static_cast<std::byte>(0x09), static_cast<std::byte>(0x18),
      static_cast<std::byte>(0x27), static_cast<std::byte>(0x36),
      static_cast<std::byte>(0xCC), static_cast<std::byte>(0xDD)};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DEAL::DEAL>());

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      key, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
  ctx.setAlgo(algo);

  ctx.encrypt(BUFFER, plain);
  ctx.decrypt(BUFFER_res, BUFFER);

  for (const auto& elem : BUFFER_res) {
    std::cout << static_cast<char>(elem);
  }

  ASSERT_EQ(BUFFER_res, plain);
}