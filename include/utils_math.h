#pragma once

#include <algorithm>
#include <boost/multiprecision/gmp.hpp>
#include <boost/random.hpp>
#include <random>

using BI = boost::multiprecision::mpz_int;

struct PublicKey {
  BI encrypt_word{};
  BI N{};
  explicit PublicKey(BI e, BI n)
      : encrypt_word(std::move(e)), N(std::move(n)) {}
};
struct PrivateKey {
  BI decrypt_word{};
  BI N{};
  explicit PrivateKey(BI d, BI n)
      : decrypt_word(std::move(d)), N(std::move(n)) {}
};