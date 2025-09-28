module;

#include "utils_math.h"

export module math;

export namespace meow::math {

BI LejandreSymbol(const BI& a, const BI& p) { return {}; }

BI JacobiSymbol(const BI& a, const BI& n) {
  if (a % n == 0) {
    return 0;
  }
  return {};
}

constexpr BI GCD(BI a, BI b) {
  while (b > 0) {
    std::tie(a, b) = std::tuple(b, a % b);
  }
  return a;
}

/*
 * Возвращает [gcd, x, y]
 * x*a+y*b=gcd
 *
 * https://ru.algorithmica.org/cs/modular/extended-euclid/
 * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 * http://e-maxx.ru/algo/extended_euclid_algorithm
 */
constexpr std::tuple<BI, BI, BI> eGCD(const BI& a, const BI& b) {
  if (a == 0) {
    return {b, 0, 1};
  }
  auto [d, x1, y1] = eGCD(b % a, a);
  BI x = y1 - (b / a) * x1;
  BI y = x1;
  return {d, x, y};
}

constexpr BI modPow(BI a, BI pow, const BI& mod) {
  a = (a % mod + mod) % mod;

  BI res = 1;

  while (pow > 0) {
    if (pow & 1) {
      res = (res * a) % mod;
    }
    a = (a * a) % mod;
    pow >>= 1;
  }
  return res;
}
}  // namespace meow::math