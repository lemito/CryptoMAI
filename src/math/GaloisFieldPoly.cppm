/**
 * матан есть тут - https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * https://vmath.ru/vf5/gruppe/galois/vspom4
 * https://vmath.ru/vf5/gruppe/galois
 * https://crypto.stackexchange.com/questions/14902/understanding-multiplication-in-the-aes-specification
 */
module;
// #include <array>
#include <algorithm>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <vector>
export module math.GaloisFieldPoly;
import <array>;
import <cstddef>;
import <tuple>;

export namespace meow::math::GaloisFieldPoly {
class GaloisFieldPoly {
  static constexpr size_t N = 1 << 8;
  static constexpr std::byte MOD_byte{
      0b00011011};  // стандартный неприводимый полином из
                    // AES, но приведенный (то есть без x^8)
  static constexpr uint16_t FULL_MOD_byte{
      0x11B};  // стандартный неприводимый полином из AES
  std::bitset<8> _bits;
  std::byte _byte{0};
  // std::array<bool, 8> _bitRepresent{};

  // constexpr void _byte2arr() {
  //   for (int16_t i = 7; i >= 0; --i) {
  //     _bitRepresent[i] = (std::to_integer<uint8_t>(_byte) & (1 << i)) != 0
  //                            ? std::byte{1}
  //                            : std::byte{0};
  //   }
  // }

  static constexpr auto plus(const std::byte& a, const std::byte& b)
      -> std::byte {
    return a ^ b;
  }

  // здесь тупо сдвиг вправо + если выход за границу - возврат
  static constexpr auto multToX(GaloisFieldPoly a, const GaloisFieldPoly& mod)
      -> GaloisFieldPoly {
    const bool hasEight =
        (std::to_integer<uint16_t>(a._byte) & 0b10000000) != 0;
    a._byte <<= 1;
    if (hasEight) {
      a._byte ^= mod._byte;
    }
    return {a};
  }

  static constexpr uint8_t _getDegree(const GaloisFieldPoly& o) {
    auto tmp = static_cast<int16_t>(o._byte);
    uint8_t res = 0;
    while (tmp > 1) {
      res++;
      tmp >>= 1;
    }
    return res;
  }

  static constexpr uint8_t _getDegree(const uint32_t& o) {
    auto tmp = o;
    uint8_t res = 0;
    while (tmp > 1) {
      res++;
      tmp >>= 1;
    }
    return res;
  }

  // 1 == k*r(x) + a(x)*q(x);
  // [q, r]
  static std::tuple<GaloisFieldPoly&&, GaloisFieldPoly&&> div_modGF(
      const GaloisFieldPoly& num, const GaloisFieldPoly& denom) {
    if (std::to_integer<uint8_t>(denom._byte) == 0) {
      throw std::invalid_argument("bad argument - denom cant be zero (0x00)");
    }
    if (std::to_integer<uint8_t>(num._byte) == 0) {
      return std::tuple{GaloisFieldPoly(static_cast<std::byte>(0x00)), num};
    }
    if (std::to_integer<uint8_t>(num._byte) ==
        std::to_integer<uint8_t>(denom._byte)) {
      return std::tuple{GaloisFieldPoly(static_cast<std::byte>(0x01)),
                        GaloisFieldPoly(static_cast<std::byte>(0x00))};
    }

    auto quo = GaloisFieldPoly();
    auto rem = num;

    auto rem_deg = _getDegree(rem);
    const auto denom_deg = _getDegree(denom);

    while (rem_deg >= denom_deg) {
      const auto shift = rem_deg - denom_deg;

      quo._byte |= static_cast<std::byte>(1 << shift);
      rem._byte ^= denom._byte << shift;
      rem_deg = _getDegree(rem);
    }

    return std::tuple{quo, rem};
  }

  static constexpr std::tuple<uint32_t, uint32_t> div_modGF(
      const uint32_t& num, const uint32_t& denom) {
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

      quo |= (1 << shift);
      rem ^= (denom << shift);
      rem_deg = _getDegree(rem);
    }

    return std::tuple{quo, rem};
  }

 public:
  GaloisFieldPoly() = default;
  GaloisFieldPoly(const GaloisFieldPoly& other) {
    _byte = other._byte;
    _bits = std::bitset<8>(std::to_integer<uint8_t>(_byte));
    // _byte2arr();
  }
  GaloisFieldPoly(const std::byte& byte) {
    _byte = byte;
    _bits = std::bitset<8>(std::to_integer<uint8_t>(_byte));
    // _byte2arr();
  }
  GaloisFieldPoly(GaloisFieldPoly&& other) noexcept : _byte(other._byte) {
    // _byte2arr();
    _bits = std::bitset<8>(std::to_integer<uint8_t>(_byte));
  }
  GaloisFieldPoly& operator=(const GaloisFieldPoly& other) {
    if (this == &other) return *this;
    _byte = other._byte;
    _bits = other._bits;
    // _byte2arr();
    return *this;
  }
  GaloisFieldPoly& operator=(GaloisFieldPoly&& other) noexcept {
    if (this == &other) return *this;
    _byte = other._byte;
    _bits = std::move(other._bits);
    // _byte2arr();
    return *this;
  }
  ~GaloisFieldPoly() = default;

  friend bool operator==(const GaloisFieldPoly& lhs,
                         const GaloisFieldPoly& rhs) {
    return lhs._byte == rhs._byte;
  }
  friend bool operator!=(const GaloisFieldPoly& lhs,
                         const GaloisFieldPoly& rhs) {
    return !(lhs == rhs);
  }

  bool operator==(const int i) const {
    return std::to_integer<int>(_byte) == i;
  }

  friend std::ostream& operator<<(std::ostream& os,
                                  const GaloisFieldPoly& obj) {
    os << "_byte: 0x" << std::hex << std::to_integer<uint16_t>(obj._byte);
    os << " _bits: " << obj._bits.to_string();
    return os;
  }

  explicit operator int() const { return std::to_integer<int>(_byte); }

  // тут по вакту делаем a(x)*b(x) % mod m(x)
  static constexpr auto mult(GaloisFieldPoly a, GaloisFieldPoly b,
                             const GaloisFieldPoly& mod) -> GaloisFieldPoly {
    std::byte res{0};
    for (int i = 0; i < 8; ++i) {
      if (std::to_integer<uint8_t>(b._byte) & 1) {
        res ^= a._byte;
      }
      a = multToX(a, mod);
      b._byte >>= 1;
    }
    return {res};
  }

  constexpr GaloisFieldPoly& operator+=(const GaloisFieldPoly& b) {
    _byte ^= b._byte;
    _bits = std::bitset<8>(std::to_integer<uint8_t>(_byte));
    return *this;
  }

  constexpr GaloisFieldPoly operator+(const GaloisFieldPoly& b) const {
    auto tmp = *this;
    tmp += b;
    return tmp;
  }

  constexpr GaloisFieldPoly& operator*=(const GaloisFieldPoly& b) {
    *this = mult(*this, b, GaloisFieldPoly(MOD_byte));
    return *this;
  }

  constexpr GaloisFieldPoly operator*(const GaloisFieldPoly& b) const {
    auto tmp = *this;
    tmp *= b;
    return tmp;
  }

  constexpr GaloisFieldPoly& operator/=(const GaloisFieldPoly& b) {
    *this = std::get<0>(div_modGF(*this, b));
    return *this;
  }

  constexpr GaloisFieldPoly operator/(const GaloisFieldPoly& b) const {
    auto tmp = *this;
    tmp /= b;
    return tmp;
  }

  constexpr GaloisFieldPoly& operator%=(const GaloisFieldPoly& b) {
    *this = std::get<1>(div_modGF(*this, b));
    return *this;
  }

  constexpr GaloisFieldPoly operator%(const GaloisFieldPoly& b) const {
    auto tmp = *this;
    tmp %= b;
    return tmp;
  }

  static constexpr auto binPowGF(const GaloisFieldPoly a, int64_t pow,
                                 const GaloisFieldPoly& mod)
      -> GaloisFieldPoly {
    if (mod == GaloisFieldPoly(static_cast<std::byte>(0))) {
      throw std::invalid_argument(std::format("bad mod=0"));
    }
    if (pow < 0) {
      throw std::invalid_argument("bad pow - only pow>=0 allowed");
    }
    if (pow == 0) {
      return {(static_cast<std::byte>(1))};
    }

    GaloisFieldPoly res{static_cast<std::byte>(1)};
    while (pow != 0) {
      if ((pow & 1)) {
        res = mult(res, a, mod);
      }
      res = mult(res, res, mod);
      pow >>= 1;
    }
    return res;
  }

  static constexpr bool isIrreducible(const uint32_t obj) {
    const auto deg = _getDegree(obj);
    const auto checkTo = 1 << ((deg / 2) + 1);

    for (uint32_t i = 2; i < checkTo; ++i) {
      if (const auto mod = std::get<1>(div_modGF(obj, i)); mod == 0) {
        return false;
      }
    }
    return true;
  }

  // следует из теоремки a^(p^n) - a = 0
  static constexpr auto invElem(const GaloisFieldPoly& obj,
                                const GaloisFieldPoly& mod) -> GaloisFieldPoly {
    return binPowGF(obj, N - 2, mod);
  }

  template <int32_t _degree>
  static constexpr auto allIrreducible() {
    static_assert(_degree >= 0, "degree cannot be negative");

    constexpr uint32_t start = 1u << _degree;
    constexpr uint32_t end = 1u << (_degree + 1);

    constexpr size_t _cnt = []() constexpr {
      size_t cnt = 0;
      for (uint32_t poly = start; poly < end; ++poly) {
        if (isIrreducible(poly)) {
          ++cnt;
        }
      }
      return cnt;
    }();

    std::array<uint32_t, _cnt> res{};
    size_t ix = 0;
    for (uint32_t poly = start; poly < end; ++poly) {
      if (isIrreducible(poly)) {
        res[ix++] = poly;
      }
    }
    return res;
  }

  static constexpr auto allIrreducibleFor8() { return allIrreducible<8>(); }
};
}  // namespace meow::math::GaloisFieldPoly