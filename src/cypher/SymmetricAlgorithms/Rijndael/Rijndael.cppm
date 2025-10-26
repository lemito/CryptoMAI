/**
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 */
module;

export module Rijndael;

import cypher.FeistelNet;

export namespace meow::cypher::symm::Rijndael {
class Rijndael : public FeistelNet::FeistelNet {};
}  // namespace meow::cypher::symm::Rijndael