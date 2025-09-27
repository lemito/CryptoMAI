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

boost::multiprecision::cpp_int gcd(const boost::multiprecision::cpp_int& a,
                                   const boost::multiprecision::cpp_int& b) {
  return {};
}

boost::multiprecision::cpp_int eGCD(const boost::multiprecision::cpp_int& a,
                                    const boost::multiprecision::cpp_int& b) {
  return {};
}

boost::multiprecision::cpp_int modPow(
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