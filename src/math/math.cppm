module;

#include <tuple>

#include "utils_math.h"

export module math;

export namespace meow::math {

/**
 * @brief рандомные чиселкт
 * @tparam Distr
 * @tparam Args
 * @param args
 * @return
 */
template <typename Distr, typename... Args>
constexpr auto _genRandNumber(Args &&...args) {
  thread_local boost::random::mt19937 generator(std::random_device{}());
  Distr dist(std::forward<Args>(args)...);
  return dist(generator);
}

/**
 * @brief метод для нормализации числа (то есть приведения его к кольцу)
 * @param number число
 * @param mod модуль
 * @return
 */
constexpr BI normalizeMod(BI number, const BI& mod) {
  if (number >= 0 && number < mod) {
    return number;
  }

  auto rem = number % mod;

  return rem < 0 ? BI(rem + mod) : rem;
}

/**
 * @brief
 * @param a
 * @param pow
 * @return
 */
constexpr BI pow(BI a, BI pow) {
  if (pow == 0) return 1;
  if (pow < 0) {
    throw std::invalid_argument("pow: степень должна быть положительной");
  }
  BI res = 1;
  while (pow > 0) {
    if (pow & 1) {
      res *= a;
    }
    a *= a;
    pow >>= 1;
  }
  return res;
}

/**
 * @brief
 * @param a
 * @param pow
 * @param mod
 * @return
 */
constexpr BI modPow(BI a, BI pow, const BI& mod) {
  if (mod == 0) {
    throw std::invalid_argument(
        std::format("низя mod=0 {}^{}", to_string(a), to_string(pow)));
  }
  if (pow == 0) return 1;
  if (pow < 0) {
    throw std::invalid_argument("modPow: степень должна быть положительной");
  }
  // a = (a % mod + mod) % mod;
  a = normalizeMod(a, mod);
  BI res = 1;
  while (pow > 0) {
    if (pow & 1) {
      res *= a;
      if (res > mod) res %= mod;
    }
    a *= a;
    if (a > mod) a %= mod;
    pow >>= 1;
  }
  if (res > mod) return res % mod;
  return res;
}

constexpr BI GCD(BI a, BI b) {
  const auto ZERO = BI(
0);
  while (b > ZERO) {
    std::tie(a, b) = std::make_tuple<BI, BI>(BI(b), a % b);
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
constexpr BI LejandreSymbol(const BI& a, const BI& p) {
  if (p <= 2) {
    throw std::invalid_argument("P должно быть > 2");
  }
  if ((p & 1) == 0) {
    throw std::invalid_argument("P должно быть нечетным");
  }

  // const BI modA = (a % p + p) % p;
  const BI modA = normalizeMod(a, p);

  if (modA == 0) {
    return 0;
  }

  // тупо волшебная формула (критерий Эйлера)
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
 * https://studfile.net/preview/4292372/page:3/
 * https://neerc.ifmo.ru/wiki/index.php?title=%D0%90%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC_%D0%B2%D1%8B%D1%87%D0%B8%D1%81%D0%BB%D0%B5%D0%BD%D0%B8%D1%8F_%D1%81%D0%B8%D0%BC%D0%B2%D0%BE%D0%BB%D0%B0_%D0%AF%D0%BA%D0%BE%D0%B1%D0%B8
 * O(loga logb)
 */
constexpr BI JacobiSymbol(const BI& a, BI n) {
  if (n <= 0) {
    throw std::invalid_argument("n должно быть > 0");
  }
  if ((n & 1) == 0) {
    throw std::invalid_argument("n должно быть нечетным");
  }

  // BI modA = a % n;
  // if (modA < 0) {
  //   modA += n;
  // }
  BI modA = normalizeMod(a, n);
  if (n == 1 || modA == 1) {
    return 1;
  }

  if (modA == 0) {
    return 0;
  }

  if (GCD(modA, n) != 1) {
    return 0;
  }

  int8_t sign = 1;
  while (modA) {
    // (4^meow|n) === (2|n)^2*meow === 1 => нафиг все что делится на 4
    // (мультпликат.)
    while (modA % 4 == 0) {
      modA /= 4;
    }
    if ((modA & 1) == 0) {
      // n==8k+r r=[1,3,5,7] n-нечет
      // (2|n) == (-1)^((n*n-1)/8) => 1(n=1,7mod8) -1(n=3,5mod8) => замена знака
      // при нечет => (n*n-1)/8 тоже нечет
      if (const auto tmp = (n * n - 1) / 8; tmp & 1) {
        sign *= -1;
      }
      modA /= 2;
    }

    if (modA > 1) {
      // https://en.wikipedia.org/wiki/Quadratic_reciprocity -- закон : (mNn) =
      // (n|m) * (-1)^{((m-1)/2)*((n-1)/2)} -< туть должен стать минус
      // (m|n)*(n|m) мб 1 [один знак] (n=m=1 mod 4) или -1[разный знак]
      // (n=m=3mod4) при перестановке => ловим второй варик
      if (modA % 4 == 3 && n % 4 == 3) {
        sign = -sign;
      }
      // и переставляем местами (n|a)==(n%a|a) поменяв знаки ранее... ну и
      // продолжаем считать
      std::tie(modA, n) = std::tuple(n % modA, modA);
    } else {
      break;
    }
  }

  return sign;
}
}  // namespace meow::math
