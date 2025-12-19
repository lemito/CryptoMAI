#ifndef MESSAGESTREAMCLIENT_H
#define MESSAGESTREAMCLIENT_H

#include <QObject>
#include <atomic>
#include <functional>
#include <memory>
#include <thread>
#include <utility>

#include "databasemanager.h"
#include "messageassembler.h"
#include "proto/chat.grpc.pb.h"
#include "proto/chat.pb.h"

class MessageStreamClient final : public QObject {
  Q_OBJECT

 public:
  using DecryptCallback =
      std::function<QByteArray(const QString&, const QByteArray&)>;

  explicit MessageStreamClient(chat::MessagingService::Stub* messagingStub,
                               DatabaseManager* dbManager,
                               QObject* parent = nullptr);
  ~MessageStreamClient();

  void startStream();
  void stopStream();
  void setDecryptCallback(DecryptCallback callback) {
    decryptCallback_ = std::move(callback);
  }
  [[nodiscard]] auto isStreaming() const -> bool { return streaming_; }

 signals:
  void messageReceived(const chat::EncryptedChunk& chunk);
  void streamError(const QString& error);
  void streamStatusChanged(bool connected);
  void messageSaved(const QString& messageId, const QString& chatId);

 private:
  void runStream();
  void processReceivedChunk(const chat::EncryptedChunk& chunk);
  void saveMessageToDatabase(const QString& messageId,
                             const QByteArray& assembledData,
                             const chat::ChunkMetadata& metadata);

  chat::MessagingService::Stub* messagingStub_;
  DatabaseManager* dbManager_;
  DecryptCallback decryptCallback_;
  std::unique_ptr<MessageAssembler> messageAssembler_;
  std::unique_ptr<grpc::ClientContext> context_;
  std::thread stream_thread_;
  std::atomic<bool> streaming_{false};
  std::atomic<bool> stop_requested_{false};
};

#endif  // MESSAGESTREAMCLIENT_H
