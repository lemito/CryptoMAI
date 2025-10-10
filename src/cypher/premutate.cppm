module;
#include <cstddef>
#include <iostream>
#include <vector>
export module cypher.permutate;

export namespace meow::cypher::premutate {
enum class bitIndexingRule : int8_t {
  LSB2MSB,  // младший->старший
  MSB2LSB   // старший->младший
};

/**
 * @brief
 * @param in
 * @param premutationRule
 * @param rule
 * @param startBitNumer
 * @return
 * пример P:[0,1,2,3] in:[a,b,c,d] => [a,b,c,d]
 * P:[2,3,0,1] in:[a,b,c,d] => [c,d,a,b]
 */
std::vector<std::byte> permutation(
    const std::vector<std::byte>& in,
    const std::vector<int64_t>& premutationRule,
    const bitIndexingRule rule = bitIndexingRule::LSB2MSB,
    const int8_t startBitNumer = 0) {
  if (startBitNumer < 0 || startBitNumer > 1) {
    throw std::runtime_error("Неправильный аргумент старта");
  }
  std::vector<std::byte> res;

  const size_t siz = in.size() * 8;
  const size_t res_siz =
      premutationRule.size() / 8 + (premutationRule.size() % 8 ? 1 : 0);
  res.resize(res_siz, static_cast<std::byte>(0));

  size_t i = 0;
  for (const auto& elem : premutationRule) {
    const auto ix = elem - static_cast<int64_t>(startBitNumer);

    if (ix < 0 || ix >= static_cast<int64_t>(siz)) {
      throw std::runtime_error("упс... чет как-то не то вышло");
    }

    const std::byte bit =
        (in[(ix / 8)] >>
         (rule == bitIndexingRule::LSB2MSB ? ix % 8 : 7 - (ix % 8))) &
        static_cast<std::byte>(1);

    res[i / 8] |=
        (bit << (rule == bitIndexingRule::LSB2MSB ? ix % 8 : 7 - (ix % 8)));

    ++i;
  }

  return res;
}

}  // namespace meow::cypher::premutate