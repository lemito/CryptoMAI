module;
export module DES;

import cypher.FeistelNet;
import cypher.permutate;
import cypher;

namespace meow::cypher::symm::DES {
class DES final : public FeistelNet::FeistelNet {};
}  // namespace meow::cypher::symm::DES