#ifndef CHATSTREAMCLIENT_H
#define CHATSTREAMCLIENT_H

#include <grpcpp/grpcpp.h>

#include <QObject>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "proto/chat.grpc.pb.h"

class ChatStreamClient : public QObject {
  Q_OBJECT
 public:
  explicit ChatStreamClient(chat::ChatService::Stub* chatStub,
                            QObject* parent = nullptr);
  ~ChatStreamClient();

  void startStream();
  void stopStream();
  [[nodiscard]] auto isStreaming() const -> bool { return streaming_; }

 signals:
  void chatReceived(const QString& chatId, const QString& partiName,
                    const ::chat::DHParameters& peerParams,
                    const ::chat::EncryptionParameters& algoParams);
  void streamError(const QString& error);
  void streamStatusChanged(bool connected);

 private:
  void runStream();
  void processChat(const chat::ChatInfo& chatInfo);

  chat::ChatService::Stub* chatStub_;
  std::atomic<bool> streaming_{false};
  std::atomic<bool> stop_requested_{false};
  std::thread stream_thread_;
  std::unique_ptr<grpc::ClientContext> context_;
  QString session_token_;
};

#endif  // CHATSTREAMCLIENT_H
