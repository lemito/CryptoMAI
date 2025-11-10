#include <grpcpp/grpcpp.h>

#include <iostream>

#include "proto/cypher.grpc.pb.h"
#include "proto/cypher.pb.h"
#include "utils_math.h"

import <vector>;
import <any>;
import <optional>;

import cypher;
import cypher.DES;
import Rijndael;

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

class CypherServiceImpl final : public crypto::CypherService::Service {
  static std::shared_ptr<meow::cypher::symm::ISymmetricCypher> createAlgorithm(
      const std::string& name) {
    if (name == "DES") {
      return std::make_shared<meow::cypher::symm::DES::DES>();
    }
    // TODO: 
    throw std::invalid_argument("Unsupported algorithm: " + name);
  }

  static BI str2BI(const std::string& str) {
    if (str.empty()) return 0;
    return BI(str);
  }

  static std::string BI2str(const BI& num) { return num.str(); }

  static std::vector<std::byte> bytes2vector(const std::string& bytes) {
    std::vector<std::byte> result;
    result.reserve(bytes.size());
    for (char c : bytes) {
      result.push_back(static_cast<std::byte>(c));
    }
    return result;
  }

 public:
  Status Encrypt(ServerContext* context, const crypto::EncryptRequest* request,
                 crypto::EncryptResponse* response) override {
    try {
      std::vector<std::byte> key = bytes2vector(request->key());
      std::vector<std::byte> data = bytes2vector(request->data());
      std::optional<std::vector<std::byte>> iv;
      std::optional<BI> iv_bigint;

      if (request->mode() == crypto::EncryptionMode::RANDOM_DELTA) {
        if (!request->iv_bigint().empty()) {
          iv_bigint = str2BI(request->iv_bigint());
        } else if (!request->iv_bytes().empty()) {
          auto bytes = bytes2vector(request->iv_bytes());
          iv_bigint = BI(request->iv_bytes());
        }
      } else if (!request->iv_bytes().empty()) {
        iv = bytes2vector(request->iv_bytes());
      }

      meow::cypher::symm::SymmetricCypherContext ctx(
          key, static_cast<meow::cypher::symm::encryptionMode>(request->mode()),
          static_cast<meow::cypher::symm::paddingMode>(request->padding()), iv,
          request->random_delta());

      auto algo = createAlgorithm(request->algorithm());
      ctx.setAlgo(algo);

      std::vector<std::byte> output;
      ctx.encrypt(output, data);

      response->set_ciphertext(
          std::string(reinterpret_cast<char*>(output.data()), output.size()));
      response->set_success(true);
      return Status::OK;
    } catch (const std::exception& e) {
      response->set_success(false);
      response->set_error(e.what());
      return Status(grpc::StatusCode::INTERNAL, e.what());
    }
  }

  Status Decrypt(ServerContext* context, const crypto::DecryptRequest* request,
                 crypto::DecryptResponse* response) override {
    try {
      std::vector<std::byte> key = bytes2vector(request->key());
      std::vector<std::byte> data = bytes2vector(request->ciphertext());
      std::optional<std::vector<std::byte>> iv;
      std::optional<BI> iv_bigint;

      if (request->mode() == crypto::EncryptionMode::RANDOM_DELTA) {
        if (!request->iv_bigint().empty()) {
          iv_bigint = str2BI(request->iv_bigint());
        } else if (!request->iv_bytes().empty()) {
          auto bytes = bytes2vector(request->iv_bytes());
          iv_bigint = BI(request->iv_bytes());
        }
      } else if (!request->iv_bytes().empty()) {
        iv = bytes2vector(request->iv_bytes());
      }

      meow::cypher::symm::SymmetricCypherContext ctx(
          key, static_cast<meow::cypher::symm::encryptionMode>(request->mode()),
          static_cast<meow::cypher::symm::paddingMode>(request->padding()), iv,
          request->random_delta());

      auto algo = createAlgorithm(request->algorithm());
      ctx.setAlgo(algo);

      std::vector<std::byte> output;
      ctx.decrypt(output, data);

      response->set_plaintext(
          std::string(reinterpret_cast<char*>(output.data()), output.size()));
      response->set_success(true);
      return Status::OK;
    } catch (const std::exception& e) {
      response->set_success(false);
      response->set_error(e.what());
      return Status(grpc::StatusCode::INTERNAL, e.what());
    }
  }
};

void RunServer(const std::string& addr) {
  CypherServiceImpl service_impl;
  ServerBuilder builder;
  builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
  builder.RegisterService(&service_impl);

  const std::unique_ptr server(builder.BuildAndStart());
  std::cout << "Crypto server listening on " << addr << std::endl;
  server->Wait();
}

auto main() -> int {
  std::cout << "1" << std::endl;
  const std::string address = "0.0.0.0:50052";
  RunServer(address);
  return 0;
}