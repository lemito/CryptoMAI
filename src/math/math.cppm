module;

#include <boost/multiprecision/cpp_int.hpp>

export module math;

export namespace meow::math {

boost::multiprecision::cpp_int lejandreSymbol(
    const boost::multiprecision::cpp_int& a,
    const boost::multiprecision::cpp_int& b) {
  return {};
}

boost::multiprecision::cpp_int jacobiSymbol(
    const boost::multiprecision::cpp_int& a,
    const boost::multiprecision::cpp_int& b) {
  return {};
}

constexpr boost::multiprecision::cpp_int GCD(boost::multiprecision::cpp_int a,
                                             boost::multiprecision::cpp_int b) {
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
constexpr std::tuple<boost::multiprecision::cpp_int,
                     boost::multiprecision::cpp_int,
                     boost::multiprecision::cpp_int>
eGCD(const boost::multiprecision::cpp_int& a,
     const boost::multiprecision::cpp_int& b) {
  if (a == 0) {
    return {b, 0, 1};
  }
  auto [d, x1, y1] = eGCD(b % a, a);
  boost::multiprecision::cpp_int x = y1 - (b / a) * x1;
  boost::multiprecision::cpp_int y = x1;
  return {d, x, y};
}

constexpr boost::multiprecision::cpp_int modPow(
    boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int pow,
    const boost::multiprecision::cpp_int& mod) {
  a = (a % mod + mod) % mod;

  boost::multiprecision::cpp_int res = 1;

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