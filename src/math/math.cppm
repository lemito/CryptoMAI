module;

#include <boost/multiprecision/cpp_int.hpp>

export module math;

export namespace meow::math {
using namespace boost::multiprecision;

cpp_int lejandreSymbol(const cpp_int& a, const cpp_int& b) { return {}; }

cpp_int jacobiSymbol(const cpp_int& a, const cpp_int& b) { return {}; }

cpp_int gcd(const cpp_int& a, const cpp_int& b) { return {}; }

cpp_int eGCD(const cpp_int& a, const cpp_int& b) { return {}; }

cpp_int modPow(cpp_int a, cpp_int pow, const cpp_int& mod) {
  a = (a % mod + mod) % mod;

  cpp_int res = 1;

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