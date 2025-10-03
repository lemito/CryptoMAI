module;

#include <boost/container/set.hpp>
#include <cstdlib>
#include <limits>
#include <print>
#include <stdexcept>

#include "utils_math.h"
import math;

export module math.PrimaryTests;

export namespace meow::math::primary {
constexpr double default_epsilon = std::numeric_limits<double>::epsilon();

constexpr bool doubleEqual(const double a, const double b,
                           const double epsilon = default_epsilon) {
  return std::abs(a - b) < epsilon;
}

constexpr bool doubleLess(const double a, const double b,
                          const double epsilon = default_epsilon) {
  return a < b && !doubleEqual(a, b, epsilon);
}

constexpr bool doubleGreaterEq(const double a, const double b,
                               const double epsilon = default_epsilon) {
  return a > b || doubleEqual(a, b, epsilon);
}

class IPrimaryTest {
 public:
  // propability [0.5, 1)
  [[nodiscard]] virtual bool isPrimary(const BI& number,
                                       double probability) const = 0;
  virtual ~IPrimaryTest() = default;
};

class AbstractPrimaryTest : public IPrimaryTest {
  static constexpr size_t probabilisticCoeff =
      2;  // для Рабина-Миллера он 4 (у него вероятность 1-1/4)
  boost::random::mt19937 randgen{static_cast<unsigned int>(std::time(nullptr))};

  [[nodiscard]] virtual bool _isPrimary(const BI& number,
                                        const BI& a) const = 0;
  [[nodiscard]] virtual BI genRandom(const BI& a, const BI& b) const {
    const boost::random::uniform_int_distribution dist(a, b);
    return dist(randgen);
  }

 public:
  [[nodiscard]] constexpr virtual size_t roundCnt(
      const double probability) const {
    if (doubleLess(probability, 0.0) || doubleEqual(probability, 0.0) ||
        doubleGreaterEq(probability, 1)) {
      throw std::invalid_argument("Вероятность точности должна быть [0; 1)");
    }

    if (probability <= default_epsilon) return 0;
    if (1.0 - probability <= default_epsilon) {
      throw std::invalid_argument("Очень близко к 1 и оч большое значение");
    }

    // 1 - (1/2)^x = proba; find x
    return static_cast<size_t>(
        std::round(-std::log(1.0 - probability) /
                   std::log(static_cast<double>(probabilisticCoeff))));
  }

  [[nodiscard]] bool isPrimary(const BI& number,
                               const double probability) const override {
    if (doubleLess(probability, 0.5) || doubleGreaterEq(probability, 1)) {
      throw std::invalid_argument("Вероятность точности должна быть [0.5; 1)");
    }
    if (number < 0) {
      throw std::invalid_argument("Допустимы только натуральные числа");
    }
    if (number == 0) {
      throw std::runtime_error("0 ни простое, ни составное");
    }
    if (number == 1) {
      throw std::runtime_error("1 ни простое, ни составное");
    }
    if (number == 2 || number == 3)
      return true;  // пусть пока так, не придумал как исправить символ Якоби и
                    // тест С-Ш

    /// TODO: тут доделать
    // const BI a = number + 100;

    const std::size_t rounds = roundCnt(probability);

    boost::container::set<BI> used_a;
    for (size_t cnt = 0; cnt < rounds; ++cnt) {
      /// TODO: тут доделать
      /// не работает для маленьких чисел, поэтому ок... пусть повторяются, хоть
      /// это и неправильно наверное
      // used_a.insert(a);
      // while (used_a.contains(a)) {
      //   a = genRandom(2, number - 2);
      //   used_a.insert(a);
      // }
      if (const auto a = genRandom(2, number - 2); !_isPrimary(number, a)) {
        return false;
      }
    }
    return true;
  }
  ~AbstractPrimaryTest() override = default;
};

class FermatTest final : public AbstractPrimaryTest {
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
    // самый добрый тест
    /// https://en.wikipedia.org/wiki/Fermat_primality_test
    /// просто должны быть взаимопросты
    /// O(klog^nloglogn) - n число; k-cnt
    if (GCD(a, number) != 1) {
      return false;
    }
    std::cout << number << " " << a << std::endl;
    return modPow(a, number - 1, number) == 1;
  }
};

/// https://en.wikipedia.org/wiki/Solovay%E2%80%93Strassen_primality_test
/// https://neerc.ifmo.ru/wiki/index.php?title=%D0%A2%D0%B5%D1%81%D1%82_%D0%A1%D0%BE%D0%BB%D0%BE%D0%B2%D0%B5%D1%8F-%D0%A8%D1%82%D1%80%D0%B0%D1%81%D1%81%D0%B5%D0%BD%D0%B0
///
class SoloveyStrassenTest final : public AbstractPrimaryTest {
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
    if ((number & 1) == 0) {
      // также костыль от якоби
      return false;
    }
    if (GCD(a, number) != 1) {
      return false;
    }
    const auto j_symbol = (JacobiSymbol(a, number) % number + number) % number;
    if (const auto exp =
            (modPow(a, (number - 1) / 2, number) % number + number) % number;
        j_symbol != exp || j_symbol == 0) {
      return false;
    }
    return true;
  }
};

class MillerRabinTest final : public AbstractPrimaryTest {
  static constexpr size_t probabilisticCoeff =
      4;  // для Рабина-Миллера он 4 (у него вероятность 1-1/4)

 public:
  [[nodiscard]] constexpr size_t roundCnt(
      const double probability) const override {
    if (doubleLess(probability, 0.0) || doubleEqual(probability, 0.0) ||
        doubleGreaterEq(probability, 1)) {
      throw std::invalid_argument("Вероятность точности должна быть [0; 1)");
    }

    if (probability <= default_epsilon) return 0;
    if (1.0 - probability <= default_epsilon) {
      throw std::invalid_argument("Очень близко к 1 и оч большое значение");
    }

    // 1 - (1/2)^x = proba; find x
    return static_cast<size_t>(
        std::round(-std::log(1.0 - probability) /
                   std::log(static_cast<double>(probabilisticCoeff))));
  }

 private:
  static constexpr std::tuple<BI, BI> getD_S(const BI& number) {
    if (number < 0) {
      throw std::invalid_argument(
          "Не умею работать с отрицательными чиселками");
    }
    // TODO: ищем s,d
    // n-1 === d*2^s; d-нечетное; n-1 скорее всего четно
    BI d = number - 1;
    BI s = 0;
    while ((d & 1) == 0) {
      d >>= 1;
      ++s;
    }
    // assert(d % 2 == 1);
    // BI tmp = d;
    // for (BI i = 0; i < s; ++i) {
    //   tmp *= 2;
    // }
    // assert(tmp == number - 1);
    return {d, s};
  }

  /// https://neerc.ifmo.ru/wiki/index.php?title=%D0%A2%D0%B5%D1%81%D1%82_%D0%9C%D0%B8%D0%BB%D0%BB%D0%B5%D1%80%D0%B0-%D0%A0%D0%B0%D0%B1%D0%B8%D0%BD%D0%B0
  /// https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
    if (GCD(a, number) != 1) {
      return false;
    }
    // TODO: доделать
    // n-1 === d*2^s; d-нечетное; n-1 скорее всего четно
    const auto [d, s] = getD_S(number);
    auto tmp = modPow(a, d, number);

    if (tmp == 1 || tmp == number - 1) {
      // самый простой случай
      return true;
    }
    // если изи не удалось, пробуем поискать благодаря s; 0 скипаем так как
    // a^1*d была выше в виде n-1
    for (BI i = 1; i < s; ++i) {
      tmp = tmp * tmp % number;
      if (tmp == number - 1) {
        // -1 mod n == n-1 mod n
        return true;
      }
    }
    return false;
  }
};
}  // namespace meow::math::primary
