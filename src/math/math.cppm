module;

#include "utils_math.h"

export module math;

export namespace meow::math {

constexpr BI modPow(BI a, BI pow, const BI& mod) {
  if (pow < 0) {
    throw std::invalid_argument("степень должна быть положительной");
  }
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

/*
 * https://en.wikipedia.org/wiki/Legendre_symbol
 * https://neerc.ifmo.ru/wiki/index.php?title=%D0%A1%D0%B8%D0%BC%D0%B2%D0%BE%D0%BB_%D0%9B%D0%B5%D0%B6%D0%B0%D0%BD%D0%B4%D1%80%D0%B0,_%D0%BA%D1%80%D0%B8%D1%82%D0%B5%D1%80%D0%B8%D0%B9_%D0%AD%D0%B9%D0%BB%D0%B5%D1%80%D0%B0
 */
BI LejandreSymbol(const BI& a, const BI& p) {
  if (p <= 2) {
    throw std::invalid_argument("P должно быть > 2");
  }
  if ((p & 1) == 0) {
    throw std::invalid_argument("P должно быть нечетным");
  }

  const BI modA = (a % p + p) % p;

  if (modA == 0) {
    return 0;
  }

  const BI pow = (p - 1) / 2;
  if (const BI res = modPow(modA, pow, p); res == 1) {
    return 1;
  } else {
    if (res == p - 1) {
      return -1;
    }
    throw std::invalid_argument("P должно быть простым");
  }
}

/*
 * https://en.wikipedia.org/wiki/Jacobi_symbol
 * https://neerc.ifmo.ru/wiki/index.php?title=%D0%90%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC_%D0%B2%D1%8B%D1%87%D0%B8%D1%81%D0%BB%D0%B5%D0%BD%D0%B8%D1%8F_%D1%81%D0%B8%D0%BC%D0%B2%D0%BE%D0%BB%D0%B0_%D0%AF%D0%BA%D0%BE%D0%B1%D0%B8
 * O(loga logb)
 */
BI JacobiSymbol(const BI& a, const BI& n) {
  if (n <= 0) {
    throw std::invalid_argument("n должно быть > 0");
  }
  if ((n & 1) == 0) {
    throw std::invalid_argument("n должно быть нечетным");
  }

  const BI modA = (a % n + n) % n;

  if (modA == 0) {
    return 0;
  }

  if (GCD(a, n) != 1) {
    return 0;
  }
  // TODO: тут доделать

  return {};
}
}  // namespace meow::math
