#include <gtest/gtest.h>

import cypher;
import Rijndael;

import <array>;
import <span>;
import <exception>;
import <iostream>;

TEST(SBox, TestSBoxGen) {
  static constexpr uint8_t exp[256] = {
      0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U,
      0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U, 0xcaU, 0x82U, 0xc9U, 0x7dU,
      0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U,
      0x72U, 0xc0U, 0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
      0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U, 0x04U, 0xc7U,
      0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U,
      0xebU, 0x27U, 0xb2U, 0x75U, 0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU,
      0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
      0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU,
      0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU, 0xd0U, 0xefU, 0xaaU, 0xfbU,
      0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU,
      0x9fU, 0xa8U, 0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
      0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U, 0xcdU, 0x0cU,
      0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU,
      0x64U, 0x5dU, 0x19U, 0x73U, 0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU,
      0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
      0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U,
      0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U, 0xe7U, 0xc8U, 0x37U, 0x6dU,
      0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU,
      0xaeU, 0x08U, 0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
      0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU, 0x70U, 0x3eU,
      0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U,
      0x86U, 0xc1U, 0x1dU, 0x9eU, 0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U,
      0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
      0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U,
      0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U};
  const auto res = meow::cypher::symm::Rijndael::Rijndael(128, 128, 0x1B);
  for (size_t i = 0; i < 256; ++i) {
    ASSERT_EQ(res._S_box[i], static_cast<std::byte>(exp[i]));
  }
}

TEST(RCon, TestRcon) {
  static constexpr uint32_t exp[] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
      0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};
  const auto res = meow::cypher::symm::Rijndael::Rijndael(128, 128, 0x1B);
  for (size_t i = 0; i < 10; ++i) {
    ASSERT_EQ(res._rcon[i], (exp[i]));
  }
}

TEST(Key, KeyGen) {
  std::vector key{
      static_cast<std::byte>(0x2b), static_cast<std::byte>(0x7e),
      static_cast<std::byte>(0x15), static_cast<std::byte>(0x16),
      static_cast<std::byte>(0x28), static_cast<std::byte>(0xae),
      static_cast<std::byte>(0xd2), static_cast<std::byte>(0xa6),
      static_cast<std::byte>(0xab), static_cast<std::byte>(0xf7),
      static_cast<std::byte>(0x15), static_cast<std::byte>(0x88),
      static_cast<std::byte>(0x09), static_cast<std::byte>(0xcf),
      static_cast<std::byte>(0x4f), static_cast<std::byte>(0x3c),
  };
  // const std::span key_span(key);
  auto res = meow::cypher::symm::Rijndael::Rijndael(128, 128, 0x1B);
  ASSERT_NO_THROW(res.keyGen(std::span(key)));
}
TEST(Rijndael, Stupid) {
  const std::vector key{
      std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
      std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
      std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
      std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}};
  const std::vector plain = {
      std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
      std::byte{0x44}, std::byte{0x55}, std::byte{0x66}, std::byte{0x77},
      std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
      std::byte{0xcc}, std::byte{0xdd}, std::byte{0xee}, std::byte{0xff}};

  constexpr std::array exp_enc = {
      std::byte{0x69}, std::byte{0xc4}, std::byte{0xe0}, std::byte{0xd8},
      std::byte{0x6a}, std::byte{0x7b}, std::byte{0x04}, std::byte{0x30},
      std::byte{0xd8}, std::byte{0xcd}, std::byte{0xb7}, std::byte{0x80},
      std::byte{0x70}, std::byte{0xb4}, std::byte{0xc5}, std::byte{0x5a}};

  std::vector<std::byte> BUFFER(plain.size() * 2);
  std::vector<std::byte> BUFFER_res(plain.size() * 2);

  const auto ptrRijndael =
      std::make_shared<meow::cypher::symm::Rijndael::Rijndael>(128, 128, 0x1B);
  // ptrRijndael->keyGen(std::span(key));

  const auto algo =
      std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
          ptrRijndael);

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      key, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
  ctx.setAlgo(algo);

  // BUFFER= algo->encrypt(plain);

  ctx.encrypt("BUFFER", "2.txt");
  ctx.decrypt("BUFFER_res", "BUFFER");

  // ASSERT_EQ(plain.size(), BUFFER_res.size());
  // ASSERT_EQ(plain, BUFFER_res);
}

// TEST(Rijndael, Stupid) {
//   std::vector key{
//       static_cast<std::byte>(0x2b), static_cast<std::byte>(0x7e),
//       static_cast<std::byte>(0x15), static_cast<std::byte>(0x16),
//       static_cast<std::byte>(0x28), static_cast<std::byte>(0xae),
//       static_cast<std::byte>(0xd2), static_cast<std::byte>(0xa6),
//       static_cast<std::byte>(0xab), static_cast<std::byte>(0xf7),
//       static_cast<std::byte>(0x15), static_cast<std::byte>(0x88),
//       static_cast<std::byte>(0x09), static_cast<std::byte>(0xcf),
//       static_cast<std::byte>(0x4f), static_cast<std::byte>(0x3c),
//   };
//   const std::vector plain = {
//       static_cast<std::byte>(0x32), static_cast<std::byte>(0x43),
//       static_cast<std::byte>(0xf6), static_cast<std::byte>(0xa8),
//       static_cast<std::byte>(0x88), static_cast<std::byte>(0x5a),
//       static_cast<std::byte>(0x30), static_cast<std::byte>(0x8d),
//       static_cast<std::byte>(0x31), static_cast<std::byte>(0x31),
//       static_cast<std::byte>(0x98), static_cast<std::byte>(0xa2),
//       static_cast<std::byte>(0xe0), static_cast<std::byte>(0x37),
//       static_cast<std::byte>(0x07), static_cast<std::byte>(0x34)};
//
//   constexpr std::array exp_enc = {
//       static_cast<std::byte>(0x39), static_cast<std::byte>(0x25),
//       static_cast<std::byte>(0x84), static_cast<std::byte>(0x1d),
//       static_cast<std::byte>(0x02), static_cast<std::byte>(0xdc),
//       static_cast<std::byte>(0x09), static_cast<std::byte>(0xfb),
//       static_cast<std::byte>(0xdc), static_cast<std::byte>(0x11),
//       static_cast<std::byte>(0x85), static_cast<std::byte>(0x97),
//       static_cast<std::byte>(0x19), static_cast<std::byte>(0x6a),
//       static_cast<std::byte>(0x0b), static_cast<std::byte>(0x32)};
//
//   std::vector<std::byte> BUFFER(plain.size());
//   std::vector<std::byte> BUFFER_res(plain.size());
//
//   const auto ptrRijndael =
//       std::make_shared<meow::cypher::symm::Rijndael::Rijndael>(128, 128,
//       0x1B);
//   // ptrRijndael->keyGen(std::span(key));
//
//   const auto algo =
//       std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
//           ptrRijndael);
//
//   auto ctx = meow::cypher::symm::SymmetricCypherContext(
//       key, meow::cypher::symm::encryptionMode::ECB,
//       meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
//   ctx.setAlgo(algo);
//
//   // BUFFER= algo->encrypt(plain);
//
//   ctx.encrypt(BUFFER, plain);
//   // ctx.decrypt(BUFFER_res, BUFFER);
//
//   for (size_t i = 0; i < exp_enc.size(); ++i) {
//     ASSERT_EQ(BUFFER[i], exp_enc[i]) << i;
//   }
//   // ASSERT_EQ(plain, BUFFER_res);
// }

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}