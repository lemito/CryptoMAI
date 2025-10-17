module;
export module DES;

import cypher.FeistelNet;
import cypher.permutate;
import cypher;

namespace meow::cypher::symm::DES {
class DESGenRoundKey : public IGenRoundKey {};

class DESEncryptionDecryption : public IEncryptionDecryption {};
}  // namespace meow::cypher::symm::DES

export namespace meow::cypher::symm::DES {
class DES final : public ISymmetricCypher {};
}  // namespace meow::cypher::symm::DES