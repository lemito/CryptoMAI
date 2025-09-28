module;

#include <cstdlib>
#include <limits>
#include <stdexcept>

#include "utils_math.h"

export module PrimaryTests;

export namespace meow::math::primary {
constexpr double default_epsilon = std::numeric_limits<double>::epsilon() * 10;

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

  [[nodiscard]] virtual bool _isPrimary(const BI& number,
                                        const BI& a) const = 0;

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

    const BI a = number + 100;

    const std::size_t rounds = roundCnt(probability);
    for (size_t cnt = 0; cnt < rounds; ++cnt) {
      std::printf("%lu\n", rounds);

      if (!_isPrimary(number, a)) {
        return false;
      }
    }
    return true;
  }
  ~AbstractPrimaryTest() override = default;
};

class FermatTest final : public AbstractPrimaryTest {
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
    return true;
  }
};

class SoloveyStrassenTest final : public AbstractPrimaryTest {
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
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
  [[nodiscard]] bool _isPrimary(const BI& number, const BI& a) const override {
    return true;
  }
};
}  // namespace meow::math::primary
