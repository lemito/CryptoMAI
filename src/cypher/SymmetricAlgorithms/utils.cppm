module;
#include <cstddef>
#include <iostream>
#include <span>
#include <vector>
export module cypher.utils;

export namespace meow::cypher {
namespace utils {
constexpr auto ShiftBytesLeft(const std::byte val, const size_t shift,
                              const size_t length) {
  return static_cast<int>((val << shift) | (val >> (length - shift))) &
         ((1 << length) - 1);
}
}  // namespace utils

namespace permutate {
enum class bitIndexingRule : int8_t {
  LSB2MSB,  // младший->старший
  MSB2LSB   // старший->младший
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
    const std::vector<std::byte>& in, const std::span<uint16_t> permutationRule,
    const bitIndexingRule rule = bitIndexingRule::LSB2MSB,
    const int8_t startBitNumer = 0) {
  if (startBitNumer < 0 || startBitNumer > 1) {
    throw std::runtime_error("Неправильный аргумент старта");
  }

  const size_t siz = in.size() * 8;
  const size_t res_siz =
      permutationRule.size() / 8 + (permutationRule.size() % 8 ? 1 : 0);
  std::vector res(res_siz, std::byte{0});

  size_t i = 0;
  for (const auto& elem : permutationRule) {
    const auto ix = elem - static_cast<int64_t>(startBitNumer);

    if (ix < 0 || ix >= static_cast<int64_t>(siz)) {
      throw std::runtime_error("упс... чет как-то не то вышло");
    }

    const bool bitVal =
        (in[ix / 8] >>
             (rule == bitIndexingRule::LSB2MSB ? ix % 8 : 7 - ix % 8) &
         static_cast<std::byte>(1)) == static_cast<std::byte>(1);

    if (bitVal) {
      res[i / 8] |= static_cast<std::byte>(
          1 << (rule == bitIndexingRule::LSB2MSB ? i % 8 : 7 - i % 8));
    }
    ++i;
  }

  return res;
}
}  // namespace permutate
}  // namespace meow::cypher