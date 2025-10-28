/**
 * матан есть тут - https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * https://vmath.ru/vf5/gruppe/galois/vspom4
 * https://vmath.ru/vf5/gruppe/galois
 * https://crypto.stackexchange.com/questions/14902/understanding-multiplication-in-the-aes-specification
 */
module;
// #include <array>
// #include <cstdint>
#include <iostream>
#include <ostream>
// #include <sstream>
// #include <vector>
export module math.GaloisFieldPoly;
import <array>;
import <cstddef>;
import <format>;
import <tuple>;
import <iterator>;
import <cstdint>;
import <vector>;
import <sstream>;
import <cstddef>;

// https://en.wikipedia.org/wiki/M%C3%B6bius_function
/**
 * @brief
 * @tparam _degree `
 * @return
 * матан снова всё порешал и количество можно подсчитать формулкой
 */
template <std::int64_t _degree>
constexpr auto _cntIrreducible() {
  static_assert(_degree >= 0, "degree cannot be negative");
  static_assert(_degree < 32, "degree very big (please use [0;32) degree)");

  throw std::runtime_error("THIS FUNCTION NOT DONE!!!!!!!!!!!!!!!");
}

constexpr auto _getDegree(const std::byte& obj) -> uint8_t {
  auto tmp = static_cast<int16_t>(obj);
  uint8_t res = 0;
  while (tmp > 1) {
    res++;
    tmp >>= 1;
  }
  return res;
}

constexpr auto _getDegree(const int64_t& obj) -> int16_t {
  if (obj > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (obj < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  if (obj == 0) {
    return -1;
  }
  auto tmp = obj;
  int16_t res = 0;
  while (tmp > 1) {
    res++;
    tmp >>= 1;
  }
  return res;
}

// 1 == k*r(x) + a(x)*q(x);
// [q, r]
auto div_modGF(const std::byte& num, const std::byte& denom)
    -> std::tuple<std::byte, std::byte> {
  if (std::to_integer<uint8_t>(denom) == 0) {
    throw std::invalid_argument("bad argument - denom cant be zero (0x00)");
  }
  if (std::to_integer<uint8_t>(num) == 0) {
    return std::tuple{static_cast<std::byte>(0x00), num};
  }
  if (num == denom) {
    return std::tuple{static_cast<std::byte>(0x01),
                      static_cast<std::byte>(0x00)};
  }

  auto quo = std::byte();
  auto rem = num;

  auto rem_deg = _getDegree(rem);
  const auto denom_deg = _getDegree(denom);

  while (rem_deg >= denom_deg) {
    const auto shift = rem_deg - denom_deg;

    quo ^= static_cast<std::byte>(1 << shift);
    rem ^= denom << shift;
    rem_deg = _getDegree(rem);
  }

  return std::tuple{quo, rem};
}

constexpr auto div_modGF(const int64_t& num, const int64_t& denom)
    -> std::tuple<uint32_t, uint32_t> {
  if (num > UINT32_MAX || denom > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (num < 0 || denom < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  if (denom == 0) {
    throw std::invalid_argument("bad argument - denom cant be zero (0x00)");
  }
  if (num == 0) {
    return std::tuple{0, num};
  }
  if (num == denom) {
    return std::tuple{1, 0};
  }

  uint32_t quo = 0;
  auto rem = num;

  auto rem_deg = _getDegree(rem);
  const auto denom_deg = _getDegree(denom);

  while (rem_deg >= denom_deg) {
    const auto shift = rem_deg - denom_deg;

    quo ^= (1 << shift);
    rem ^= (denom << shift);
    rem_deg = _getDegree(rem);
  }

  return std::tuple{quo, rem};
}

export namespace meow::math::GaloisFieldPoly {
constinit size_t N = 1 << 8;
constinit std::byte MOD_byte{
    0b00011011};  // стандартный неприводимый полином из
                  // AES, но приведенный (то есть без x^8)
constinit uint16_t FULL_MOD_byte{
    0x11B};  // стандартный неприводимый полином из AES

constexpr auto plus(const std::byte& a, const std::byte& b) -> std::byte {
  return a ^ b;
}

// здесь тупо сдвиг вправо + если выход за границу - возврат
constexpr auto multToX(std::byte a, const std::byte& mod) -> std::byte {
  const bool hasEight = (std::to_integer<uint16_t>(a) & 0b10000000) != 0;
  a <<= 1;
  if (hasEight) {
    a ^= mod;
  }
  return a;
}

constexpr auto div(const int64_t a, const int64_t b) {
  if (a > UINT32_MAX || b > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (a < 0 || b < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  return std::get<0>(div_modGF(a, b));
}

constexpr auto mod(const int64_t a, const int64_t b) {
  if (a > UINT32_MAX || b > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (a < 0 || b < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  return std::get<1>(div_modGF(a, b));
}

// тут по вакту делаем a(x)*b(x) % mod m(x)
constexpr auto mult(std::byte a, std::byte b, const std::byte& mod)
    -> std::byte {
  if (std::to_integer<uint8_t>(mod) == 0) {
    throw std::invalid_argument("mod cant be == 0");
  }
  std::byte res{0};
  for (int i = 0; i < 8; ++i) {
    if ((std::to_integer<uint8_t>(b) & 1) != 0) {
      res ^= a;
    }
    a = multToX(a, mod);
    b >>= 1;
  }
  return res;
}

constexpr auto binPowGF(const std::byte num, int64_t pow, const std::byte& mod)
    -> std::byte {
  if (mod == static_cast<std::byte>(0)) {
    throw std::invalid_argument(std::format("bad mod=0"));
  }
  if (pow < 0) {
    throw std::invalid_argument("bad pow - only pow>=0 allowed");
  }
  if (pow == 0) {
    return static_cast<std::byte>(1);
  }

  auto res{static_cast<std::byte>(1)};
  while (pow != 0) {
    if ((pow & 1)) {
      res = mult(res, num, mod);
    }
    res = mult(res, res, mod);
    pow >>= 1;
  }
  return res;
}

constexpr auto isIrreducible(const int64_t poly) -> bool {
  if (poly > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (poly < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  const auto deg = _getDegree(poly);
  const uint32_t checkTo = 1 << ((deg / 2) + 1);

  for (uint32_t i = 2; i < checkTo; ++i) {
    if (const auto mod = std::get<1>(div_modGF(poly, i)); mod == 0) {
      return false;
    }
  }
  return true;
}

// следует из теоремки a^(p^n) - a = 0
constexpr auto invElem(const std::byte& obj, const std::byte& mod)
    -> std::byte {
  return binPowGF(obj, N - 2, mod);
}

constexpr auto allIrreducible(const int16_t _degree) {
  if (_degree < 0) {
    throw std::invalid_argument("degree cannot be negative");
  }
  if (_degree > 32) {
    throw std::invalid_argument("degree very big (please use [0;32) degree");
  }

  const uint32_t start = 1U << _degree;
  const uint32_t end = 1U << (_degree + 1);

  std::vector<uint32_t> res{};
  for (uint32_t poly = start; poly < end; ++poly) {
    if (isIrreducible(poly)) {
      res.push_back(poly);
    }
  }
  return res;
}

constexpr auto allIrreducibleFor8() { return allIrreducible(8); }

constexpr auto decomposition(int64_t poly) -> std::vector<uint32_t> {
  if (poly > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (poly < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  if (poly == 0) {
    return {};
  }

  const auto deg = _getDegree(poly);
  if (deg == 0) {
    return {1};
  }

  if (isIrreducible(poly)) {
    return {static_cast<uint32_t>(poly)};
  }

  std::vector<uint32_t> pre_res;
  for (int16_t i = 1; i <= (deg / 2); ++i) {
    auto irr = allIrreducible(i);
    pre_res.insert(pre_res.end(), std::make_move_iterator(irr.begin()),
                   std::make_move_iterator(irr.end()));
  }

  std::vector<uint32_t> res;

  for (const auto irredPoly : pre_res) {
    while (std::get<1>(div_modGF(poly, irredPoly)) == 0) {
      res.push_back(irredPoly);
      poly = std::get<0>(div_modGF(poly, irredPoly));

      if (poly == 1) {
        return res;
      }

      if (isIrreducible(poly)) {
        res.push_back(poly);
        return res;
      }
    }
  }

  if (poly != 1) {
    res.push_back(poly);
  }

  return res;
}

constexpr auto to_string(const int64_t poly) -> std::string {
  if (poly > UINT32_MAX) {
    throw std::runtime_error("polynom must be max 31 degree");
  }
  if (poly < 0) {
    throw std::runtime_error("polynom cant be negative");
  }
  if (poly == 0) {
    return "0";
  }
  std::stringstream meow;

  const auto deg = _getDegree(poly);
  // TODO::
  for (int16_t i = 1; i < deg; ++i) {
    if (1 == ((poly >> i) & 1)) {
      if (meow.str().length() > 0) {
        meow << " + ";
      }

      switch (i) {
        case 0:
          meow << "1";
          break;
        case 1:
          meow << "x";
          break;
        default:
          meow << std::format("x^{}", i);
          break;
      }
    }
  }

  return meow.str();
}

auto operator<<(std::ostream& os, const std::byte o) -> std::ostream& {
  os << std::hex << std::to_integer<uint8_t>(o) << ' ';
  os << to_string(static_cast<int64_t>(o));
  return os;
}

}  // namespace meow::math::GaloisFieldPoly