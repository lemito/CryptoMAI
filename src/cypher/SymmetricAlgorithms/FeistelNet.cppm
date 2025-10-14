module;

#include <memory>
#include <ranges>
#include <vector>

export module cypher.FeistelNet;
import cypher;

std::tuple<std::vector<std::byte>, std::vector<std::byte>> splitBlock(
    const std::vector<std::byte>& in) {
  const size_t ix = in.size() / 2;
  auto first = in | std::views::take(ix);
  auto second = in | std::views::drop(ix);
  return {{first.begin(), first.end()}, {second.begin(), second.end()}};
}

std::vector<std::byte> mergeBlock(const std::vector<std::byte>& a,
                                  const std::vector<std::byte>& b) {
  std::vector res(a.begin(), a.end());
  res.insert(res.end(), b.begin(), b.end());
  return res;
}

std::vector<std::byte> xorSpan(const std::vector<std::byte>& a,
                               const std::vector<std::byte>& b) {
  if (a.size() != b.size()) {
    throw std::runtime_error("блоки должны быть одного размера");
  }
  std::vector res(a.begin(), a.end());
  for (size_t i = 0; i < a.size(); i++) {
    res[i] = a[i] ^ b[i];
  }
  return res;
}

export namespace meow::cypher::symm::FeistelNet {

class FeistelNet : public ISymmetricCypher {
  [[nodiscard]] std::vector<std::byte> _network(
      const std::vector<std::byte>& in,
      const std::vector<std::vector<std::byte>>& _roundKeys) const {
    auto [L, R] = splitBlock(in);
    for (std::size_t i = 0; i < in.size(); i++) {
      // TODO: тут будет код
      const auto F_res = this->_enc_dec->encrypt_decrypt(R, _roundKeys[i]);
      R = xorSpan(L, F_res);
      L = R;
      // std::tie(R, L) = std::tuple(
      //     xorSpan(L, this->_enc_dec->encrypt_decrypt(R, _roundKeys[i])), R);
    }
    return mergeBlock(R, L);
  }

 protected:
  const std::vector<std::byte> _key{};
  size_t _rounds{};
  std::shared_ptr<IGenRoundKey> _keyGenerator{};
  std::shared_ptr<IEncryptionDecryption> _enc_dec{};

 public:
  explicit FeistelNet(const std::vector<std::byte>& key, const size_t rounds,
                      const std::shared_ptr<IGenRoundKey>& keyGenerator,
                      const std::shared_ptr<IEncryptionDecryption>& dec_dec)
      : _key(key),
        _rounds(rounds),
        _keyGenerator(std::move(keyGenerator)),
        _enc_dec(std::move(dec_dec)) {
    FeistelNet::setRoundKeys(key);
  }

  constexpr void setRoundKeys(
      const std::vector<std::byte>& encryptionKey) override {
    _roundKeys = _keyGenerator->genRoundKeys(encryptionKey);
  }

  [[nodiscard]] constexpr std::vector<std::byte> encrypt(
      const std::vector<std::byte>& in) const override {
    const auto roundKeys = this->getRoundKeys();
    if (roundKeys.empty()) {
      throw std::runtime_error("ключ не установлен! шифрование невозможно");
    }
    if (const auto siz = in.size(); siz & 1) {
      throw std::runtime_error("размер сообщения должен быть кратен 2");
    }
    return _network(in, roundKeys);
  }

  [[nodiscard]] constexpr std::vector<std::byte> decrypt(
      const std::vector<std::byte>& in) const override {
    const auto roundKeys = this->getRoundKeys();
    if (roundKeys.empty()) {
      throw std::runtime_error("ключ не установлен! шифрование невозможно");
    }
    if (const auto siz = in.size(); siz & 1) {
      throw std::runtime_error("размер сообщения должен быть кратен 2");
    }
    return _network(in, roundKeys);
  }
};
}  // namespace meow::cypher::symm::FeistelNet