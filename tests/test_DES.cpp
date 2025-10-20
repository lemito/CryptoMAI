#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

import cypher;
import cypher.DES;

bool isFilesEqual(const std::string& filePath1, const std::string& filePath2) {
  std::ifstream file1(filePath1, std::ios::binary);
  std::ifstream file2(filePath2, std::ios::binary);

  if (!file1.is_open() || !file2.is_open()) {
    return false;
  }

  file1.seekg(0, std::ios::end);
  file2.seekg(0, std::ios::end);

  const std::streamsize size1 = file1.tellg();
  const std::streamsize size2 = file2.tellg();

  if (size1 != size2) {
    return false;
  }

  file1.seekg(0, std::ios::beg);
  file2.seekg(0, std::ios::beg);

  constexpr std::streamsize BUFFER_SIZE = 64 * 1024;
  std::vector<char> buffer1(BUFFER_SIZE);
  std::vector<char> buffer2(BUFFER_SIZE);

  std::streamsize bytesRead1, bytesRead2;

  do {
    file1.read(buffer1.data(), BUFFER_SIZE);
    file2.read(buffer2.data(), BUFFER_SIZE);

    bytesRead1 = file1.gcount();
    bytesRead2 = file2.gcount();

    if (bytesRead1 != bytesRead2) {
      return false;
    }

    if (std::memcmp(buffer1.data(), buffer2.data(), bytesRead1) != 0) {
      return false;
    }

  } while (bytesRead1 > 0);

  return true;
}

TEST(SBox, FindRC) {
  auto [r, c] =
      meow::cypher::symm::_detailDES::DESEncryptionDecryption::_findIxSBlock(
          static_cast<std::byte>(0b00101111));
  ASSERT_EQ(r, 3);
  ASSERT_EQ(c, 7);
}

TEST(SBox, FindNewByte) {
  const auto res1 =
      meow::cypher::symm::_detailDES::DESEncryptionDecryption::_findNewElem(
          meow::cypher::symm::_detailDES::DESEncryptionDecryption::
              _findIxSBlock(static_cast<std::byte>(0b00101111)),
          0);
  const auto res8 =
      meow::cypher::symm::_detailDES::DESEncryptionDecryption::_findNewElem(
          meow::cypher::symm::_detailDES::DESEncryptionDecryption::
              _findIxSBlock(static_cast<std::byte>(0b00101111)),
          7);
  ASSERT_EQ(res1, static_cast<std::byte>(7));
  ASSERT_EQ(res8, static_cast<std::byte>(13));
}

TEST(DES, Error) {
  constexpr std::vector<std::byte> key = {};

  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DES::DES>());
  ASSERT_THROW(algo->setRoundKeys(key), std::runtime_error);
}

TEST(DES, BadKey) {
  const std::vector key = {std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                           std::byte{0x78}, std::byte{0x9A}, std::byte{0xBC},
                           std::byte{0xDE}, std::byte{0xF0}};
  std::vector plain = {static_cast<std::byte>('m'), static_cast<std::byte>('e'),
                       static_cast<std::byte>('o'),
                       static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER;
  std::vector<std::byte> BUFFER_res;
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DES::DES>());
  ASSERT_THROW(algo->setRoundKeys(key), BadDESKey);
}

TEST(DES, SimpleWithPad) {
  const std::vector key = {
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
          std::make_shared<meow::cypher::symm::DES::DES>());

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

TEST(DES, Simple) {
  const std::vector key = {
      static_cast<std::byte>(0xAA), static_cast<std::byte>(0xBB),
      static_cast<std::byte>(0x09), static_cast<std::byte>(0x18),
      static_cast<std::byte>(0x27), static_cast<std::byte>(0x36),
      static_cast<std::byte>(0xCC), static_cast<std::byte>(0xDD)};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DES::DES>());

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

TEST(DES, SimpleFile) {
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

  ctx.encrypt("BUFFER", "plain");
  ctx.decrypt("BUFFER_res", "BUFFER");

  ASSERT_TRUE(isFilesEqual("plain", "BUFFER_res"));
}

TEST(DES, BigFile) {
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

  ctx.encrypt("buf", "3.txt");
  ctx.decrypt("buf_res", "buf");

  ASSERT_TRUE(isFilesEqual("3.txt", "buf_res"));
}

TEST(DES, BiggestFile) {
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

  ctx.encrypt("buffy", "4.txt");
  ctx.decrypt("buffy_res", "buffy");

  ASSERT_TRUE(isFilesEqual("4.txt", "buffy_res"));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}