#include <any>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <vector>

import cypher;
import cypher.DES;

auto main() -> int {
  const std::vector key = {
      static_cast<std::byte>(0xAA), static_cast<std::byte>(0xBB),
      static_cast<std::byte>(0x09), static_cast<std::byte>(0x18),
      static_cast<std::byte>(0x27), static_cast<std::byte>(0x36),
      static_cast<std::byte>(0xCC), static_cast<std::byte>(0xDD)};

  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DES::DES>());

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      key, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
  ctx.setAlgo(algo);

  ctx.encrypt("./buffy", "./3.txt");
  ctx.decrypt("./buffy_res", "./buffy");

  return 0;
}