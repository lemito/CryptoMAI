#include "databasemanager.h"
#include <QApplication>
#include <QFile>

std::unique_ptr<DatabaseManager> DatabaseManager::m_instance = nullptr;

auto DatabaseManager::instance() -> DatabaseManager*
{
  if (!m_instance) {
    m_instance = std::make_unique<DatabaseManager>();
  }
  return m_instance.get();
}

void DatabaseManager::destroyInstance()
{
  if (m_instance) {
    m_instance->close();
    m_instance.reset();
  }
}

DatabaseManager::DatabaseManager(QObject* parent)
    : QObject(parent)
{
}

DatabaseManager::~DatabaseManager()
{
  close();
}

auto DatabaseManager::getDBPath() -> QString
{
  QString path = QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation);
  QDir dir(path);
  if (!dir.exists()) {
    dir.mkpath(".");
  }
  return dir.filePath("cryptomai_chat.db");
}

auto DatabaseManager::init() -> bool
{
  QString dbPath = getDBPath();
  qDebug() << "БД живет:" << dbPath;

  m_database = QSqlDatabase::addDatabase("QSQLITE");
  m_database.setDatabaseName(dbPath);

  if (!m_database.open()) {
    qCritical() << "ошибка:" << m_database.lastError().text();
    return false;
  }

  QSqlQuery query;
  query.exec("PRAGMA foreign_keys = ON");
  query.exec("PRAGMA journal_mode = WAL");
  query.exec("PRAGMA synchronous = NORMAL");

  return createTables();
}

auto DatabaseManager::createTables() -> bool
{
  QSqlQuery query;

  bool success = query.exec(
      "CREATE TABLE IF NOT EXISTS chats ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "chat_id TEXT UNIQUE NOT NULL,"
      "name TEXT NOT NULL,"
      "last_message_text BLOB,"
      "last_message_time DATETIME,"
      "unread_count INTEGER DEFAULT 0,"
      "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
      ")"
      );

  if (!success) {
    qCritical() << "не удалось создать табличку:" << query.lastError().text();
    return false;
  }

  success = query.exec(
      "CREATE TABLE IF NOT EXISTS messages ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "chat_id TEXT NOT NULL,"
      "message_id TEXT UNIQUE NOT NULL,"
      "sender TEXT NOT NULL,"
      "content BLOB NOT NULL,"
      "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "is_encrypted BOOLEAN DEFAULT FALSE,"
      "is_outgoing BOOLEAN DEFAULT FALSE,"
      "status INTEGER DEFAULT 0,"  // 0=sent, 1=delivered, 2=read
      "FOREIGN KEY (chat_id) REFERENCES chats (chat_id) ON DELETE CASCADE"
      ")"
      );

  if (!success) {
    qCritical() << "не удалось создать табличку:" << query.lastError().text();
    return false;
  }

  query.exec("CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)");
  query.exec("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)");
  query.exec("CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id)");
  query.exec("CREATE INDEX IF NOT EXISTS idx_chats_last_message ON chats(last_message_time)");

  qDebug() << "все таблички создались";
  return true;
}

void DatabaseManager::close()
{
  if (m_database.isOpen()) {
    m_database.close();
  }
}

auto DatabaseManager::addMessage(const QString& chatId, const QString& messageId,
                                 const QString& sender, const QByteArray& content,
                                 bool isEncrypted, bool isOutgoing, MessageStatus status) -> bool
{
  QSqlQuery query;
  query.prepare(
      "INSERT INTO messages (chat_id, message_id, sender, content, is_encrypted, is_outgoing, status) "
      "VALUES (?, ?, ?, ?, ?, ?, ?)"
      );
  query.addBindValue(chatId);
  query.addBindValue(messageId);
  query.addBindValue(sender);
  query.addBindValue(content);
  query.addBindValue(isEncrypted);
  query.addBindValue(isOutgoing);
  query.addBindValue(static_cast<int>(status));

  bool success = query.exec();
  if (success) {
    QSqlQuery updateChat;
    updateChat.prepare(
        "UPDATE chats SET last_message_text = ?, last_message_time = CURRENT_TIMESTAMP "
        "WHERE chat_id = ?"
        );
    updateChat.addBindValue(content);
    updateChat.addBindValue(chatId);
    updateChat.exec();

    if (!isOutgoing) {
      QSqlQuery updateUnread;
      updateUnread.prepare(
          "UPDATE chats SET unread_count = unread_count + 1 WHERE chat_id = ?"
          );
      updateUnread.addBindValue(chatId);
      updateUnread.exec();
    }

    qDebug() << "Соо сохранено:" << messageId;
  } else {
    qCritical() << "ошибка:" << query.lastError().text();
  }
  return success;
}

auto DatabaseManager::getChatMessages(const QString& chatId, int limit, int offset) -> QVector<Message>
{
  QVector<Message> messages;
  QSqlQuery query;
  query.prepare(
      "SELECT id, chat_id, message_id, sender, content, timestamp, is_encrypted, is_outgoing, status "
      "FROM messages WHERE chat_id = ? ORDER BY timestamp ASC LIMIT ? OFFSET ?"
      );
  query.addBindValue(chatId);
  query.addBindValue(limit);
  query.addBindValue(offset);

  if (query.exec()) {
    while (query.next()) {
      Message msg;
      msg.id = query.value(0).toLongLong();
      msg.chatId = query.value(1).toString();
      msg.messageId = query.value(2).toString();
      msg.sender = query.value(3).toString();
      msg.content = query.value(4).toByteArray();
      msg.timestamp = query.value(5).toDateTime();
      msg.isEncrypted = query.value(6).toBool();
      msg.isOutgoing = query.value(7).toBool();
      msg.status = static_cast<MessageStatus>(query.value(8).toInt());
      messages.append(msg);
    }
  } else {
    qCritical() << "ошибка получения соо:" << query.lastError().text();
  }
  return messages;
}

auto DatabaseManager::updateMessageStatus(const QString& messageId, MessageStatus status) -> bool
{
  QSqlQuery query;
  query.prepare("UPDATE messages SET status = ? WHERE message_id = ?");
  query.addBindValue(static_cast<int>(status));
  query.addBindValue(messageId);

  return query.exec();
}

auto DatabaseManager::markMessagesAsRead(const QString& chatId) -> bool
{
  QSqlQuery query;
  query.prepare(
      "UPDATE messages SET status = ? WHERE chat_id = ? AND is_outgoing = FALSE"
      );
  query.addBindValue(static_cast<int>(MessageStatus::READ));
  query.addBindValue(chatId);

  bool success = query.exec();
  if (success) {
    QSqlQuery updateChat;
    updateChat.prepare("UPDATE chats SET unread_count = 0 WHERE chat_id = ?");
    updateChat.addBindValue(chatId);
    updateChat.exec();
  }

  return success;
}

auto DatabaseManager::getUnreadCount(const QString& chatId) -> int
{
  QSqlQuery query;
  query.prepare("SELECT unread_count FROM chats WHERE chat_id = ?");
  query.addBindValue(chatId);

  if (query.exec() && query.next()) {
    return query.value(0).toInt();
  }
  return 0;
}

