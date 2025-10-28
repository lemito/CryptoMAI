/**
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 */
module;

export module Rijndael;
import cypher;
import <cstddef>;
import <vector>;

export namespace meow::cypher::symm::Rijndael {
class Rijndael final : public meow::cypher::symm::IGenRoundKey,
                       meow::cypher::symm::IEncryptionDecryption,
                       meow::cypher::symm::ISymmetricCypher {
 public:
  [[nodiscard("")]] constexpr std ::vector<std ::vector<std ::byte>>
  genRoundKeys(const std ::vector<std ::byte>& inputKey) const override {
    // TODO: Implement this pure virtual method.
    static_assert(false, "Method `genRoundKeys` is not implemented.");
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encryptDecryptBlock(
      const std ::vector<std ::byte>& inputBlock,
      const std ::vector<std ::byte>& roundKey) const override {
    // TODO: Implement this pure virtual method.
    static_assert(false, "Method `encryptDecryptBlock` is not implemented.");
  }

  constexpr void setRoundKeys(
      const std ::vector<std ::byte>& encryptionKey) override {
    // TODO: Implement this pure virtual method.
    static_assert(false, "Method `setRoundKeys` is not implemented.");
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> encrypt(
      const std ::vector<std ::byte>& in) const override {
    // TODO: Implement this pure virtual method.
    static_assert(false, "Method `encrypt` is not implemented.");
  }

  [[nodiscard("")]] constexpr std ::vector<std ::byte> decrypt(
      const std ::vector<std ::byte>& in) const override {
    // TODO: Implement this pure virtual method.
    static_assert(false, "Method `decrypt` is not implemented.");
  }
};

}  // namespace meow::cypher::symm::Rijndael