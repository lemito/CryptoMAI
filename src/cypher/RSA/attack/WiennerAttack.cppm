module;

#include <ranges>
#include <vector>

#include "utils_math.h"

export module cypher.RSA.WiennerAttack;

export namespace meow::cypher::RSA::attack {
class WiennerAttackService {
 public:
  struct Fraction {
    BI numerator;
    BI denominator;

    bool operator==(const Fraction& other) const {
      return numerator == other.numerator && denominator == other.denominator;
    }

    friend std::ostream& operator<<(std::ostream& ofs,
                                    const Fraction& fraction) {
      ofs << fraction.numerator << "/" << fraction.denominator;
      return ofs;
    }
  };
  class ContinuedFraction {
   public:
    static constexpr std::vector<BI> calcCoeffs(const Fraction& fr) {
      std::vector<BI> coefficients;
      auto a = fr.numerator;
      auto b = fr.denominator;

      // разложение по простому правилу: делим на цело и сохраняем, меняем
      // местами: числитель=знаменатель, знаменатель-остаток от деления
      while (b > 0) {
        coefficients.emplace_back(a / b);
        std::tie(a, b) = std::make_tuple<BI, BI>(BI(b), a % b);
      }
      return coefficients;
    }

    static constexpr std::vector<Fraction> convergentsCF(
        const std::vector<BI>& coefficients) {
      std::vector<Fraction> convergents;
      BI a = 1;
      BI b = 0;

      BI c = coefficients[0];
      BI d = 1;

      // convergents.push_back({a, b});
      convergents.push_back({c, d});

      for (const auto& coeff : coefficients | std::views::drop(1)) {
        // c = c*coeff + a;
        // d = d*coeff + b;
        /// приближенная дробь p/q: (1/0), (a0/1), далее pi = p_(i-1)*ai+p_(i2)
        /// 1i = 1_(i-1)*ai+1_(i-2)
        std::tie(a, b, c, d) = std::make_tuple<BI, BI, BI, BI>(
            BI(c), BI(d), c * coeff + a, d * coeff + b);
        convergents.emplace_back(c, d);
      }

      return convergents;
    }
  };
  WiennerAttackService() = default;

  struct HackRes {
    BI decrypt_exp;
    BI phi;
    std::vector<Fraction> convergents;
  };

  static constexpr HackRes hack(const BI& e, const BI& N) {
    auto solve_quadratic = [](const BI& sum_pq,
                              const BI& N) -> std::pair<BI, BI> {
      const BI discr = sum_pq * sum_pq - 4 * N;
      if (discr < 0) {
        return {0, 0};
      }

      const BI sqrt = boost::multiprecision::sqrt(discr);
      if (sqrt * sqrt != discr) {
        return {0, 0};
      }

      const BI p = (sum_pq + sqrt) / 2;
      const BI q = (sum_pq - sqrt) / 2;

      return {p, q};
    };
    // d == e^-1 mod N => ed = 1 + k*phi; e/phi - k/d = 1/d*phi -> e/N - k/d <
    // 1/dphi < 1/2d^2
    // ==> цепная дробь и приближенная к ней содержит
    const Fraction fr{e, N};
    const auto coefs = ContinuedFraction::calcCoeffs(fr);

    for (const auto convs = ContinuedFraction::convergentsCF(coefs);
         const auto& [numerator, denominator] : convs | std::views::drop(0)) {
      const BI Ki = numerator;
      const BI Di = denominator;  // потенциальный дешифратор
      if (Ki == 0) continue;
      const BI ed1 = e * Di - 1;
      if (ed1 % Ki != 0) continue;
      const BI phi = ed1 / Ki;

      // x^2 - (-phi + N + 1)x + N = 0
      // 1x^2 + bx + c = 0
      const BI b = N + 1 - phi;

      if (const auto [P, Q] = solve_quadratic(b, N);
          P * Q == N && P > 0 && Q > 0) {
        std::cout << "Ха-ха, я взломал твоё сообщение" << std::endl;
        return {Di, phi, convs};
      } else {
        std::cout << "Не подходит: P*Q=" << (P * Q) << " (ожидалось " << N
                  << ")" << "P= " << P << " Q=" << Q << "Ki= " << Ki
                  << " Di= " << Di << " b= " << b << std::endl;
      }
    }

    throw std::runtime_error("Не удалось взломать милое сообщение");
  }
};
}  // namespace meow::cypher::RSA::attack