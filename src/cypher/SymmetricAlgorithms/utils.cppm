module;
#include <cstddef>
#include <iostream>
#include <span>
#include <vector>
export module cypher.utils;

export namespace meow::cypher {
namespace utils {
constexpr auto ShiftBytesLeft(const std::uint64_t val, const size_t shift,
                              const size_t length) {
  // return static_cast<uint64_t>((val << shift) | (val >> (length - shift))) &
  //        ((1 << length) - 1);
  return (val << shift | val >> 28 - shift) &
         0x0FFFFFFF;
}
}  // namespace utils

namespace permutate {
enum class bitIndexingRule : int8_t {
  LSB2MSB,  // младший->старший == little endian
  MSB2LSB   // старший->младший == big-endian
};

/**
 * @brief
 * @param in
 * @param permutationRule
 * @param rule
 * @param startBitNumer
 * @return
 * пример P:[0,1,2,3] in:[a,b,c,d] => [a,b,c,d]
 * P:[2,3,0,1] in:[a,b,c,d] => [c,d,a,b]
 */
constexpr std::vector<std::byte> permutation(
    const std::vector<std::byte>& in,
    const std::span<uint16_t>& permutationRule,
    const bitIndexingRule rule = bitIndexingRule::LSB2MSB,
    const int8_t startBitNumer = 0) {
  if (startBitNumer < 0 || startBitNumer > 1) {
    throw std::runtime_error("Неправильный аргумент старта");
  }

  const size_t siz = in.size() * 8;
  const size_t res_siz =
      permutationRule.size() / 8 + (permutationRule.size() % 8 ? 1 : 0);
  std::vector res(res_siz, std::byte{0});

  for (size_t i = 0; i < permutationRule.size(); i++) {
    const auto ix = permutationRule[i] - static_cast<int64_t>(startBitNumer);

    if (ix < 0 || ix >= static_cast<int64_t>(siz)) {
      throw std::runtime_error("упс... чет как-то не то вышло в перестановках");
    }

    const auto byteIx = ix / 8;
    const auto bitIx = rule == bitIndexingRule::MSB2LSB ? ix % 8 : 7 - (ix % 8);
    const auto newByteIx = i / 8;
    const auto newBitIx =
        rule == bitIndexingRule::MSB2LSB ? 7 - (i % 8) : i % 8;

    const bool bit =
        (std::to_integer<int16_t>(in[byteIx] >> (7 - bitIx)) & 1) == 1;

    if (bit) {
      res[newByteIx] |= static_cast<std::byte>(1 << newBitIx);
    }
  }

  return res;
}
}  // namespace permutate
}  // namespace meow::cypher