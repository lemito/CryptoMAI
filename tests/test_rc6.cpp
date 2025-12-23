#include <gtest/gtest.h>

#include <fstream>
#include <span>
#include <string>
#include <vector>

#include "debug.h"
#include "utils_math.h"

import cypher;
import cypher.rc6;

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

TEST(RC6, SimpleWithPad) {
  const std::vector key{
    std::byte{0x8e}, std::byte{0x73}, std::byte{0xb0}, std::byte{0xf7},
    std::byte{0xda}, std::byte{0x0e}, std::byte{0x64}, std::byte{0x52},
    std::byte{0xc8}, std::byte{0x10}, std::byte{0xf3}, std::byte{0x2b},
    std::byte{0x80}, std::byte{0x90}, std::byte{0x79}, std::byte{0xe5},
    std::byte{0x62}, std::byte{0xf8}, std::byte{0xea}, std::byte{0xd2},
    std::byte{0x52}, std::byte{0x2c}, std::byte{0x6b}, std::byte{0x7b}};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::RC6::RC6>());

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

TEST(RC6, Simple) {
  const std::vector key{
    std::byte{0x8e}, std::byte{0x73}, std::byte{0xb0}, std::byte{0xf7},
    std::byte{0xda}, std::byte{0x0e}, std::byte{0x64}, std::byte{0x52},
    std::byte{0xc8}, std::byte{0x10}, std::byte{0xf3}, std::byte{0x2b},
    std::byte{0x80}, std::byte{0x90}, std::byte{0x79}, std::byte{0xe5},
    std::byte{0x62}, std::byte{0xf8}, std::byte{0xea}, std::byte{0xd2},
    std::byte{0x52}, std::byte{0x2c}, std::byte{0x6b}, std::byte{0x7b}};
  const std::vector plain = {
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w'),
      static_cast<std::byte>('m'), static_cast<std::byte>('e'),
      static_cast<std::byte>('o'), static_cast<std::byte>('w')};

  std::vector<std::byte> BUFFER(plain.size());
  std::vector<std::byte> BUFFER_res(plain.size());
  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::RC6::RC6>());

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

TEST(RC6, ALL) {
  const std::vector key{
    std::byte{0x8e}, std::byte{0x73}, std::byte{0xb0}, std::byte{0xf7},
    std::byte{0xda}, std::byte{0x0e}, std::byte{0x64}, std::byte{0x52},
    std::byte{0xc8}, std::byte{0x10}, std::byte{0xf3}, std::byte{0x2b},
    std::byte{0x80}, std::byte{0x90}, std::byte{0x79}, std::byte{0xe5},
    std::byte{0x62}, std::byte{0xf8}, std::byte{0xea}, std::byte{0xd2},
    std::byte{0x52}, std::byte{0x2c}, std::byte{0x6b}, std::byte{0x7b}};

  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          std::make_shared<meow::cypher::symm::RC6::RC6>());

  const std::vector IV{
    static_cast<std::byte>(0x32), static_cast<std::byte>(0x43),
    static_cast<std::byte>(0xf6), static_cast<std::byte>(0xa8),
    static_cast<std::byte>(0x88), static_cast<std::byte>(0x5a),
    static_cast<std::byte>(0x30), static_cast<std::byte>(0x8d),
    static_cast<std::byte>(0x31), static_cast<std::byte>(0x31),
    static_cast<std::byte>(0x98), static_cast<std::byte>(0xa2),
    static_cast<std::byte>(0xe0), static_cast<std::byte>(0x37),
    static_cast<std::byte>(0x07), static_cast<std::byte>(0x34)};

  for (size_t mode = 0; mode < 7; ++mode) {
    for (size_t pad = 0; pad < 4; ++pad) {
      auto ctx = meow::cypher::symm::SymmetricCypherContext(
          key, static_cast<meow::cypher::symm::encryptionMode>(mode),
          static_cast<meow::cypher::symm::paddingMode>(pad), IV, BI(52));
      ctx.setAlgo(algo);

      std::string pref = std::to_string(mode) + "_" + std::to_string(pad);

      ctx.encrypt(pref + "BUFFER", "2.txt");
      ctx.decrypt(pref + "BUFFER_res_rc6", pref + "BUFFER");

      ASSERT_TRUE(isFilesEqual("2.txt", pref + "BUFFER_res_rc6"));
    }
  }
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}