module;
export module cypher.rc6;

import cypher.FeistelNet;
import cypher.utils;
import cypher;

export namespace meow::cypher::symm::RC6 {
class RC6 final : public FeistelNet::FeistelNet {};
}  // namespace meow::cypher::symm::RC6