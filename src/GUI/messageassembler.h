#ifndef MESSAGEASSEMBLER_H
#define MESSAGEASSEMBLER_H

#include <QByteArray>
#include <QDateTime>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QTimer>
#include <memory>

#include "absl/container/flat_hash_map.h"
#include "proto/chat.pb.h"
#include "utils.hpp"

class MessageAssembler final : public QObject {
  Q_OBJECT

 public:
  explicit MessageAssembler(QObject* parent = nullptr);
  ~MessageAssembler();

 public slots:
  void processChunk(const chat::EncryptedChunk& chunk);
  void cleanupExpiredMessages();

 signals:
  void messageComplete(const QString& messageId,
                       const QByteArray& assembledData,
                       const chat::ChunkMetadata& metadata);
  void assemblyError(const QString& messageId, const QString& error);

 private:
  struct MessageAssembly {
    QString messageId;
    QString chatId;
    QString fileId;
    QString originalFilename;
    int64_t fileSize = 0;
    int totalChunks = 0;
    int receivedChunks = 0;
    bool isFile = false;
    bool isCancellation = false;
    QMap<int, QByteArray> chunks;  // chunk_index -> data
    QSet<int> receivedIndices;
    QTimer* timeoutTimer = nullptr;
    QDateTime createdTime;
  };

  QMap<QString, MessageAssembly> assemblies_;
  QTimer cleanupTimer_;

  void checkAssemblyComplete(MessageAssembly& assembly);
  void finalizeMessage(MessageAssembly& assembly);
  void cleanupMessage(const QString& messageId);
};

#endif  // MESSAGEASSEMBLER_H
