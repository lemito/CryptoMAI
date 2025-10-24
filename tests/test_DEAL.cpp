#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

import cypher;
import cypher.DEAL;

bool isFilesEqual(const std::string& filePath1, const std::string& filePath2) {
  std::ifstream file1(filePath1, std::ios::binary);
  std::ifstream file2(filePath2, std::ios::binary);

  if (!file1.is_open() || !file2.is_open()) {
    return false;
  }

  file1.seekg(0, std::ios::end);
  file2.seekg(0, std::ios::end);

  if (file1.tellg() != file2.tellg()) {
    std::cerr << "Размеры разные " << std::endl;
    return false;
  }

  file1.seekg(0, std::ios::beg);
  file2.seekg(0, std::ios::beg);

  constexpr std::streamsize BUFFER_SIZE = 64 * 1024;
  std::vector<char> buffer1(BUFFER_SIZE);
  std::vector<char> buffer2(BUFFER_SIZE);

  while (file1 && file2) {
    file1.read(buffer1.data(), BUFFER_SIZE);
    file2.read(buffer2.data(), BUFFER_SIZE);

    const std::streamsize bytesRead1 = file1.gcount();
    const std::streamsize bytesRead2 = file2.gcount();

    if (bytesRead1 != bytesRead2) {
      return false;
    }

    if (bytesRead1 == 0) {
      break;
    }

    if (std::memcmp(buffer1.data(), buffer2.data(), bytesRead1) != 0) {
      std::cerr << "Данные разные " << std::endl;
      return false;
    }
  }

  return !file1.bad() && !file2.bad() && file1.eof() && file2.eof();
}

TEST(DEAL, Simple) {
  const std::vector key = {
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00)};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DEAL::DEALAdapter>());

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

TEST(DEAL, Simple2) {
  const std::vector key = {
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00)};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('='), static_cast<std::byte>('U'),
      static_cast<std::byte>('w'), static_cast<std::byte>('U'),
      static_cast<std::byte>('=')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DEAL::DEALAdapter>());

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

TEST(DEAL, SimpleFile) {
  const std::vector key = {
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0x00), static_cast<std::byte>(0x00)};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('='), static_cast<std::byte>('U'),
      static_cast<std::byte>('w'), static_cast<std::byte>('U'),
      static_cast<std::byte>('=')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::DEAL::DEALAdapter>());

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      key, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
  ctx.setAlgo(algo);

  ctx.encrypt("dealBuf", "1.txt");
  ctx.decrypt("dealBuf_res", "dealBuf");

  ASSERT_TRUE(isFilesEqual("1.txt", "dealBuf_res"));
}