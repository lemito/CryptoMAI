#ifndef CHAT_STRUCTS_H
#define CHAT_STRUCTS_H

#include <QDateTime>
#include <QString>

#include "cypher/SymmetricAlgorithms/cypher.hpp"

struct Chat {
  qint64 id{0};
  QString chatId{""};
  QString name{""};
  QString creatorName{""};
  QDateTime createdAt{};

  QString algorithm{""};
  QString padding{""};
  QString mode{""};
  QString iv{""};

  QByteArray key{};
  QString privateKey{""};

  QString prime{"0"};
  QString generator{"0"};
  QString publicKey{"0"};
  QString peerPublicKey{"0"};
  bool dhExchangeComplete{false};
};

enum class MessageStatus : std::uint8_t { SENT = 0, DELIVERED = 1, READ = 2 };

struct Message {
  qint64 id{0};
  QString chatId{""};
  QString messageId{""};
  QString sender{""};
  QByteArray content{};
  QDateTime timestamp{};
  bool isEncrypted{true};
  bool isOutgoing{};
  MessageStatus status;

  bool isFile{false};
  QString fileName{""};
  QString mimeType{""};
  qint64 fileSize{0};
  QString originalFilename{""};
};

#endif  // CHAT_STRUCTS_H
