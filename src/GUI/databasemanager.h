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

struct Chat {
  qint64 id;
  QString chatId;
  QString name;
  QDateTime createdAt;
};

enum class MessageStatus : std::uint8_t { SENT = 0, DELIVERED = 1, READ = 2 };

struct Message {
  qint64 id;
  QString chatId;
  QString messageId;
  QString sender;
  QByteArray content;
  QDateTime timestamp;
  bool isEncrypted;
  bool isOutgoing;       // true - исходящее, false - входящее
  MessageStatus status;  // sent, delivered, read
};

class DatabaseManager : public QObject {
  Q_OBJECT
 public:
  static DatabaseManager* instance();
  static void destroyInstance();

  auto init() -> bool;
  void close();

  // ========= ОПЕРАЦИИ НАД ЧАТОМ ==============
  auto addChat(const QString& chatId, const QString& name) -> bool;
  auto removeChat(const QString& chatId) -> bool;
  auto getAllChats() -> QVector<Chat>;
  auto getChat(const QString& chatId) -> Chat;

  // =========  ОПЕРАЦИИ НАД СОО  ==============
  auto addMessage(const QString& chatId, const QString& messageId,
                  const QString& sender, const QByteArray& content,
                  bool isEncrypted = false, bool isOutgoing = false,
                  MessageStatus status = MessageStatus::SENT) -> bool;
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

  explicit DatabaseManager(QObject* parent = nullptr);
  ~DatabaseManager();

 private:
  auto createTables() -> bool;
  auto getDBPath() -> QString;
  QSqlDatabase m_database;

  static std::unique_ptr<DatabaseManager> m_instance;
};

#endif  // DATABASEMANAGER_H
