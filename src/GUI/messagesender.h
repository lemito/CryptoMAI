#ifndef MESSAGESENDER_H
#define MESSAGESENDER_H

#include <QObject>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

#include "absl/synchronization/mutex.h"
#include "databasemanager.h"
#include "proto/chat.grpc.pb.h"
#include "proto/chat.pb.h"

class MessageSender : public QObject {
  Q_OBJECT

 public:
  using EncryptCallback =
      std::function<QByteArray(const QString&, const QByteArray&)>;

  explicit MessageSender(chat::MessagingService::Stub* messagingStub,
                         DatabaseManager* dbManager, QObject* parent = nullptr);
  ~MessageSender();

  void sendMessage(const QString& chatId, const QByteArray& data,
                   bool isFile = false);
  void sendFile(const QString& chatId, const QString& filePath);
  void sendFileInfo(const QString& chatId, const QString& fileId,
                    const QString& originalFileName, qint64 originalFileSize,
                    const QString& mimeType, bool isFile);
  void setEncryptCallback(EncryptCallback callback) {
    encryptCallback_ = callback;
  }

 private:
  void runSender();
  auto prepareChunks(const QString& chatId, const QByteArray& originalData,
                     const QByteArray& encryptedData, bool isFile)
      -> std::vector<chat::EncryptedChunk>;
  auto createMetadata(const QString& chatId, const QString& messageId,
                      const QString& fileId, const QString& originalFilename,
                      qint64 originalFileSize, const QString& mimeType,
                      bool isFile, int totalChunks, int chunkIndex)
      -> chat::ChunkMetadata;

  chat::MessagingService::Stub* messagingStub_;
  DatabaseManager* dbManager_;
  EncryptCallback encryptCallback_;
  std::thread sender_thread_;
  std::atomic<bool> stop_requested_{false};
  absl::Mutex queue_mutex_;
  absl::CondVar condition_;
  std::queue<std::vector<chat::EncryptedChunk>> chunks_queue_;
};

#endif  // MESSAGESENDER_H
