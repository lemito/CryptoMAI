#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QDebug>
#include <QDir>
#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QString>
#include <memory>

#include "absl/container/flat_hash_map.h"
#include "chat_structs.h"

class DatabaseManager final : public QObject {
  Q_OBJECT
 public:
  static auto instance() -> DatabaseManager*;
  static void destroyInstance();

  auto init() -> bool;
  void close();

  // ========= ОПЕРАЦИИ НАД ЧАТОМ ==============
  auto addChat(const QString& chatId, const QString& name,
               const QString& createdName, const QString& algorithm,
               const QString& mode, const QString& padding, const QString& iv,
               const QString& initiator, const QString& prime,
               const QString& generator, const QString& publicKey,
               const QString& peerPublicKey, bool dhExchangeComplete) -> bool;
  auto removeChat(const QString& chatId) -> bool;
  auto getAllChats(const QString& username) -> QVector<Chat>;
  auto getChat(const QString& chatId, const QString& username) -> Chat;
  auto updateChatParams(const QString& chatId, const QString& prime,
                        const QString& generator, const QString& peerPublicKey,
                        const QString& iv) -> bool;

  // =========  ОПЕРАЦИИ НАД СОО  ==============
  auto addMessage(const QString& chatId, const QString& messageId,
                  const QString& sender, const QByteArray& content,
                  bool isEncrypted, bool isOutgoing, MessageStatus status,
                  bool isFile, const QString& fileName, const QString& mimeType,
                  qint64 fileSize, const QString& createdName,
                  const QString& originalFilename = QString()) -> bool;
  auto updateMessageStatus(const QString& messageId, MessageStatus status)
      -> bool;
  auto updateMessageContent(const QString& messageId, const QByteArray& content)
      -> bool;
  auto getChatMessages(const QString& chatId, int limit = 100, int offset = 0)
      -> QVector<Message>;
  auto getUnreadMessages(const QString& chatId) -> QVector<Message>;
  auto markMessagesAsRead(const QString& chatId) -> bool;
  auto deleteMessage(const QString& messageId) -> bool;
  auto clearChatHistory(const QString& chatId) -> bool;
  auto getUnreadCount(const QString& chatId) -> int;

  auto addFileMessage(const QString& chatId, const QString& messageId,
                      const QString& sender, const QByteArray& fileData,
                      const QString& fileName, const QString& mimeType,
                      bool isOutgoing, MessageStatus status) -> bool;

  auto getChatFiles(const QString& chatId) -> QVector<Message>;

  auto getFileStats(const QString& chatId)
      -> absl::flat_hash_map<QString, qint64>;

  auto updateFileInfo(const QString& messageId, const QString& fileName,
                      const QString& mimeType, qint64 fileSize) -> bool;

  auto clearFileContent(const QString& messageId) -> bool;

  auto getFileMessageByFileId(const QString& fileId) -> Message;
  auto updateMessageFilePath(const QString& messageId, const QString& filePath)
      -> bool;

  explicit DatabaseManager(QObject* parent = nullptr);
  ~DatabaseManager();

 private:
  auto createTables() -> bool;
  static auto getDBPath() -> QString;
  QSqlDatabase m_database;

  static std::unique_ptr<DatabaseManager> m_instance;
};

#endif  // DATABASEMANAGER_H
