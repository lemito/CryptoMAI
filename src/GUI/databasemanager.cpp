#include "databasemanager.h"

#include <QApplication>
#include <QFile>

std::unique_ptr<DatabaseManager> DatabaseManager::m_instance = nullptr;

auto DatabaseManager::instance() -> DatabaseManager* {
  if (!m_instance) {
    m_instance = std::make_unique<DatabaseManager>();
  }
  return m_instance.get();
}

void DatabaseManager::destroyInstance() {
  if (m_instance) {
    m_instance->close();
    m_instance.reset();
  }
  qDebug() << "DatabaseManageInstancer изнечтожен";
}

DatabaseManager::DatabaseManager(QObject* parent) : QObject(parent) {}

DatabaseManager::~DatabaseManager() { close(); }

auto DatabaseManager::getDBPath() -> QString {
  QString path =
      QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
  QDir dir(path);
  if (!dir.exists()) {
    dir.mkpath(".");
  }
  return dir.filePath("cryptomai_chat.db");
}

auto DatabaseManager::init() -> bool {
  QString dbPath = getDBPath();
  qDebug() << "БД живет:" << dbPath;

  if (!m_database.contains("QSQLITE")) {
    m_database = QSqlDatabase::addDatabase("QSQLITE");
    m_database.setDatabaseName(dbPath);
  }

  if (!m_database.open()) {
    qCritical() << "ошибка:" << m_database.lastError().text();
    return false;
  }

  QSqlQuery query(m_database);
  query.exec("PRAGMA foreign_keys = ON");
  query.exec("PRAGMA journal_mode = WAL");
  query.exec("PRAGMA synchronous = NORMAL");

  return createTables();
}

auto DatabaseManager::createTables() -> bool {
  QSqlQuery query(m_database);

  bool success = query.exec(
      "CREATE TABLE IF NOT EXISTS chats ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "chat_id TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "created_name TEXT NOT NULL,"
      "last_message_text BLOB,"
      "last_message_time DATETIME,"
      "unread_count INTEGER DEFAULT 0,"
      "created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "algorithm TEXT,"
      "mode TEXT,"
      "padding TEXT,"
      "iv TEXT,"
      "prime TEXT,"
      "generator TEXT,"
      "public_key TEXT,"
      "peer_public_key TEXT,"
      "dh_exchange_complete BOOLEAN DEFAULT FALSE,"
      "UNIQUE(chat_id, created_name)"
      ")");

  if (!success) {
    qCritical() << "не удалось создать табличку:" << query.lastError().text();
    return false;
  }

  success = query.exec(
      "CREATE TABLE IF NOT EXISTS messages ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "chat_id TEXT NOT NULL,"
      "created_name TEXT NOT NULL,"
      "message_id TEXT UNIQUE NOT NULL,"
      "sender TEXT NOT NULL,"
      "content BLOB NOT NULL,"
      "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "is_encrypted BOOLEAN DEFAULT FALSE,"
      "is_outgoing BOOLEAN DEFAULT FALSE,"
      "status INTEGER DEFAULT 0,"  // 0=sent, 1=delivered, 2=read
      "is_file BOOLEAN DEFAULT FALSE,"
      "file_name TEXT,"
      "mime_type TEXT,"
      "file_size INTEGER DEFAULT 0,"
      "original_filename TEXT,"
      "FOREIGN KEY (chat_id, created_name) REFERENCES chats (chat_id, "
      "created_name) ON DELETE CASCADE"
      ")");

  query.exec("ALTER TABLE messages ADD COLUMN original_filename TEXT");

  if (!success) {
    qCritical() << "не удалось создать табличку:" << query.lastError().text();
    return false;
  }

  success = query.exec(
      "CREATE TABLE IF NOT EXISTS encryption_keys ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "chat_id TEXT NOT NULL,"
      "username TEXT NOT NULL,"
      "key_data BLOB NOT NULL,"
      "created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "algorithm TEXT,"
      "key_size INTEGER,"
      "is_active BOOLEAN DEFAULT TRUE,"
      "FOREIGN KEY (chat_id) REFERENCES chats (chat_id) ON DELETE CASCADE,"
      "UNIQUE(chat_id, username)"
      ")");

  if (!success) {
    qCritical() << "не удалось создать табличку encryption_keys:"
                << query.lastError().text();
    return false;
  }

  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)");
  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON "
      "messages(timestamp)");
  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_messages_message_id ON "
      "messages(message_id)");
  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_messages_is_file ON messages(is_file)");
  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_chats_last_message ON "
      "chats(last_message_time)");
  query.exec(
      "CREATE INDEX IF NOT EXISTS idx_encryption_keys_chat_user ON "
      "encryption_keys(chat_id, username)");

  qDebug() << "все таблички создались";
  return true;
}

void DatabaseManager::close() {
  if (m_database.isOpen()) {
    m_database.close();
  }
}

auto DatabaseManager::addChat(
    const QString& chatId, const QString& name, const QString& createdName,
    const QString& algorithm, const QString& mode, const QString& padding,
    const QString& iv, const QString& initiator, const QString& prime,
    const QString& generator, const QString& publicKey,
    const QString& peerPublicKey, bool dhExchangeComplete) -> bool {
  QSqlQuery checkQuery;
  checkQuery.prepare("SELECT COUNT(*) FROM chats WHERE chat_id = ?");
  checkQuery.addBindValue(chatId);

  if (!checkQuery.exec()) {
    qCritical() << "Ошибка проверки существования чата:"
                << checkQuery.lastError().text();
    return false;
  }

  QSqlQuery query(m_database);
  query.prepare(
      "INSERT INTO chats (chat_id, name, created_name, last_message_text, "
      "last_message_time, unread_count, algorithm, mode, padding, iv, "
      "prime, generator, public_key, peer_public_key, dh_exchange_complete) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

  query.addBindValue(chatId);
  query.addBindValue(name);
  query.addBindValue(createdName);
  query.addBindValue(QByteArray());
  query.addBindValue(QDateTime::currentDateTime());
  query.addBindValue(0);
  query.addBindValue(algorithm);
  query.addBindValue(mode);
  query.addBindValue(padding);
  query.addBindValue(iv);
  query.addBindValue(prime);
  query.addBindValue(generator);
  query.addBindValue(publicKey);
  query.addBindValue(peerPublicKey);
  query.addBindValue(dhExchangeComplete);

  bool success = query.exec();
  if (success) {
    qDebug() << "Чат создан:" << chatId << name << "создатель:" << createdName;
  } else {
    qCritical() << "Ошибка создания чата:" << query.lastError().text();
  }
  return success;
}

auto DatabaseManager::removeChat(const QString& chatId) -> bool {
  QSqlDatabase::database().transaction();

  QSqlQuery deleteMessagesQuery;
  deleteMessagesQuery.prepare("DELETE FROM messages WHERE chat_id = ?");
  deleteMessagesQuery.addBindValue(chatId);

  if (!deleteMessagesQuery.exec()) {
    qCritical() << "Ошибка удаления сообщений чата:"
                << deleteMessagesQuery.lastError().text();
    QSqlDatabase::database().rollback();
    return false;
  }

  QSqlQuery deleteChatQuery;
  deleteChatQuery.prepare("DELETE FROM chats WHERE chat_id = ?");
  deleteChatQuery.addBindValue(chatId);

  bool success = deleteChatQuery.exec();
  if (success) {
    QSqlDatabase::database().commit();
    qDebug() << "Чат удален:" << chatId;
  } else {
    QSqlDatabase::database().rollback();
    qCritical() << "Ошибка удаления чата:"
                << deleteChatQuery.lastError().text();
  }

  return success;
}

auto DatabaseManager::getAllChats(const QString& username) -> QVector<Chat> {
  QVector<Chat> chats;
  QSqlQuery query(m_database);

  QString sql =
      "SELECT id, chat_id, name, created_name, created_at, algorithm, "
      "padding, mode, iv, prime, generator, public_key, peer_public_key, "
      "dh_exchange_complete "
      "FROM chats ";

  if (!username.isEmpty()) {
    sql += "WHERE created_name = ? ";
    sql += "ORDER BY last_message_time DESC, created_at DESC";
    query.prepare(sql);
    query.addBindValue(username);
  } else {
    sql += "ORDER BY last_message_time DESC, created_at DESC";
    query.prepare(sql);
  }

  if (query.exec()) {
    while (query.next()) {
      Chat chat;
      chat.id = query.value(0).toLongLong();
      chat.chatId = query.value(1).toString();
      chat.name = query.value(2).toString();
      chat.creatorName = query.value(3).toString();
      chat.createdAt = query.value(4).toDateTime();
      chat.algorithm = query.value(5).toString();
      chat.padding = query.value(6).toString();
      chat.mode = query.value(7).toString();
      chat.iv = query.value(8).toString();
      chat.prime = query.value(9).toString();
      chat.generator = query.value(10).toString();
      chat.publicKey = query.value(11).toString();
      chat.peerPublicKey = query.value(12).toString();
      chat.dhExchangeComplete = query.value(13).toBool();
      chats.append(chat);
    }
  } else {
    qCritical() << "Ошибка получения списка чатов:" << query.lastError().text();
    qCritical() << "Запрос:" << query.lastQuery();
  }
  return chats;
}

auto DatabaseManager::getChat(const QString& chatId, const QString& username)
    -> Chat {
  Chat chat;
  QSqlQuery query(m_database);
  QString sql;

  if (!username.isEmpty() && !username.isNull()) {
    sql =
        "SELECT id, chat_id, name, created_name, created_at, "
        "algorithm, padding, mode, iv, prime, generator, "
        "public_key, peer_public_key, dh_exchange_complete "
        "FROM chats "
        "WHERE chat_id = :chatId AND created_name = :username "
        "ORDER BY last_message_time DESC, created_at DESC "
        "LIMIT 1";

    query.prepare(sql);
    query.bindValue(":chatId", chatId);
    query.bindValue(":username", username);
  } else {
    sql =
        "SELECT id, chat_id, name, created_name, created_at, "
        "algorithm, padding, mode, iv, prime, generator, "
        "public_key, peer_public_key, dh_exchange_complete "
        "FROM chats "
        "WHERE chat_id = :chatId "
        "ORDER BY last_message_time DESC, created_at DESC "
        "LIMIT 1";

    query.prepare(sql);
    query.bindValue(":chatId", chatId);
  }

  if (!query.exec()) {
    qCritical() << "Ошибка выполнения запроса получения чата:"
                << query.lastError().text() << "\nЗапрос:" << query.lastQuery();
    return chat;
  }

  if (query.next()) {
    chat.id = query.value("id").toLongLong();
    chat.chatId = query.value("chat_id").toString();
    chat.name = query.value("name").toString();
    chat.creatorName = query.value("created_name").toString();
    chat.createdAt = query.value("created_at").toDateTime();
    chat.algorithm = query.value("algorithm").toString();
    chat.padding = query.value("padding").toString();
    chat.mode = query.value("mode").toString();
    chat.iv = query.value("iv").toString();
    chat.prime = query.value("prime").toString();
    chat.generator = query.value("generator").toString();
    chat.publicKey = query.value("public_key").toString();
    chat.peerPublicKey = query.value("peer_public_key").toString();
    chat.dhExchangeComplete = query.value("dh_exchange_complete").toBool();
  } else {
    qDebug() << "Чат не найден. chatId:" << chatId << "username:" << username;
    chat.chatId = "";
  }

  return chat;
}

auto DatabaseManager::addMessage(
    const QString& chatId, const QString& messageId, const QString& sender,
    const QByteArray& content, bool isEncrypted, bool isOutgoing,
    MessageStatus status, bool isFile, const QString& fileName,
    const QString& mimeType, qint64 fileSize, const QString& createdName,
    const QString& originalFilename) -> bool {
  if (isEncrypted) {
    qCritical() << "БЫЛО ДОГОВОРЕНИЕ, ЧТО isEncrypted false";
  }

  QSqlQuery query(m_database);
  bool prep = query.prepare(
      "INSERT INTO messages (chat_id, created_name, message_id, sender, "
      "content, "
      "is_encrypted, is_outgoing, status, is_file, file_name, mime_type, "
      "file_size, original_filename) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

  if (!prep) {
    qCritical() << "Query prepare failed:" << query.lastError().text();
    return false;
  }
  query.addBindValue(chatId);
  query.addBindValue(createdName);
  query.addBindValue(messageId);
  query.addBindValue(sender);
  query.addBindValue(content);
  query.addBindValue(isEncrypted);
  query.addBindValue(isOutgoing);
  query.addBindValue(static_cast<int>(status));
  query.addBindValue(isFile);
  query.addBindValue(fileName);
  query.addBindValue(mimeType);
  query.addBindValue(fileSize);
  query.addBindValue(originalFilename);

  bool success = query.exec();
  if (success) {
    QString previewText;
    if (isFile) {
      previewText = QString("[Файл] %1").arg(fileName);
    } else {
      QString text = QString::fromUtf8(content);
      previewText = text.left(50) + (text.length() > 50 ? "..." : "");
    }

    QSqlQuery updateChat;
    updateChat.prepare(
        "UPDATE chats SET last_message_text = ?, last_message_time = "
        "CURRENT_TIMESTAMP "
        "WHERE chat_id = ? AND created_name = ?");
    updateChat.addBindValue(previewText.toUtf8());
    updateChat.addBindValue(chatId);
    updateChat.addBindValue(createdName);
    updateChat.exec();

    if (!isOutgoing) {
      QSqlQuery updateUnread;
      updateUnread.prepare(
          "UPDATE chats SET unread_count = unread_count + 1 "
          "WHERE chat_id = ? AND created_name = ?");
      updateUnread.addBindValue(chatId);
      updateUnread.addBindValue(createdName);
      updateUnread.exec();
    }

    qDebug() << "Сообщение сохранено:" << messageId
             << (isFile ? QString("(файл: %1)").arg(fileName) : "");
  } else {
    qCritical() << "Ошибка сохранения сообщения:" << query.lastError().text();
    qCritical() << "Запрос:" << query.lastQuery();
    qCritical() << "Параметры: chatId=" << chatId
                << "createdName=" << createdName << "sender=" << sender;
  }
  return success;
}

auto DatabaseManager::getChatMessages(const QString& chatId, int limit,
                                      int offset) -> QVector<Message> {
  QVector<Message> messages;
  QSqlQuery query(m_database);

  query.prepare(
      "SELECT "
      "id, "
      "chat_id, "
      "created_name, "
      "message_id, "
      "sender, "
      "content, "
      "timestamp, "
      "is_encrypted, "
      "is_outgoing, "
      "status, "
      "is_file, "
      "file_name, "
      "mime_type, "
      "file_size, "
      "original_filename "
      "FROM messages "
      "WHERE chat_id = ? "
      "ORDER BY timestamp ASC "
      "LIMIT ? OFFSET ?");

  query.addBindValue(chatId);
  query.addBindValue(limit);
  query.addBindValue(offset);

  if (query.exec()) {
    while (query.next()) {
      Message msg;
      msg.id = query.value(0).toLongLong();
      msg.chatId = query.value(1).toString();
      // query.value(2)
      msg.messageId = query.value(3).toString();
      msg.sender = query.value(4).toString();
      msg.content = query.value(5).toByteArray();
      msg.timestamp = query.value(6).toDateTime();
      msg.isEncrypted = query.value(7).toBool();
      msg.isOutgoing = query.value(8).toBool();
      msg.status = static_cast<MessageStatus>(query.value(9).toInt());
      msg.isFile = query.value(10).toBool();

      if (msg.isFile) {
        msg.fileName = query.value(11).toString();
        msg.mimeType = query.value(12).toString();
        msg.fileSize = query.value(13).toLongLong();
        msg.originalFilename = query.value(14).toString();
      }

      messages.append(msg);
    }
  } else {
    qCritical() << "Ошибка получения сообщений:" << query.lastError().text();
    qCritical() << "Запрос:" << query.lastQuery();
  }

  qDebug() << "Загружено" << messages.size() << "сообщений для чата" << chatId;
  return messages;
}

auto DatabaseManager::updateMessageStatus(const QString& messageId,
                                          MessageStatus status) -> bool {
  QSqlQuery query(m_database);
  query.prepare("UPDATE messages SET status = ? WHERE message_id = ?");
  query.addBindValue(static_cast<int>(status));
  query.addBindValue(messageId);

  return query.exec();
}

auto DatabaseManager::markMessagesAsRead(const QString& chatId) -> bool {
  QSqlQuery query(m_database);
  query.prepare(
      "UPDATE messages SET status = ? WHERE chat_id = ? AND is_outgoing = "
      "FALSE");
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

auto DatabaseManager::getUnreadCount(const QString& chatId) -> int {
  QSqlQuery query(m_database);
  query.prepare("SELECT unread_count FROM chats WHERE chat_id = ?");
  query.addBindValue(chatId);

  if (query.exec() && query.next()) {
    return query.value(0).toInt();
  }
  return 0;
}

auto DatabaseManager::updateFileInfo(const QString& messageId,
                                     const QString& fileName,
                                     const QString& mimeType, qint64 fileSize)
    -> bool {
  QSqlQuery query(m_database);
  query.prepare(
      "UPDATE messages SET file_name = ?, mime_type = ?, file_size = ? "
      "WHERE message_id = ?");
  query.addBindValue(fileName);
  query.addBindValue(mimeType);
  query.addBindValue(fileSize);
  query.addBindValue(messageId);

  return query.exec();
}

auto DatabaseManager::updateChatParams(const QString& chatId,
                                       const QString& prime,
                                       const QString& generator,
                                       const QString& peerPublicKey,
                                       const QString& iv) -> bool {
  QSqlQuery query(m_database);
  query.prepare(
      "UPDATE chats SET prime = :prime, generator = :generator, "
      "peer_public_key = :peerPublicKey, iv = :iv, dh_exchange_complete = "
      ":dhComplete "
      "WHERE chat_id = :chatId");

  query.bindValue(":chatId", chatId);
  query.bindValue(":prime", prime);
  query.bindValue(":generator", generator);
  query.bindValue(":peerPublicKey", peerPublicKey);
  query.bindValue(":iv", iv);
  query.bindValue(":dhComplete", !peerPublicKey.isEmpty());

  return query.exec();
}

auto DatabaseManager::getFileMessageByFileId(const QString& fileId) -> Message {
  Message msg;
  QSqlQuery query(m_database);
  query.prepare(
      "SELECT id, chat_id, created_name, message_id, sender, content, "
      "timestamp, is_encrypted, is_outgoing, status, is_file, file_name, "
      "mime_type, file_size, original_filename "
      "FROM messages WHERE file_name = ? AND is_file = TRUE LIMIT 1");
  query.addBindValue(fileId);

  if (query.exec() && query.next()) {
    msg.id = query.value(0).toLongLong();
    msg.chatId = query.value(1).toString();
    msg.messageId = query.value(3).toString();
    msg.sender = query.value(4).toString();
    msg.content = query.value(5).toByteArray();
    msg.timestamp = query.value(6).toDateTime();
    msg.isEncrypted = query.value(7).toBool();
    msg.isOutgoing = query.value(8).toBool();
    msg.status = static_cast<MessageStatus>(query.value(9).toInt());
    msg.isFile = query.value(10).toBool();
    msg.fileName = query.value(11).toString();
    msg.mimeType = query.value(12).toString();
    msg.fileSize = query.value(13).toLongLong();
    msg.originalFilename = query.value(14).toString();
  }

  return msg;
}

auto DatabaseManager::updateMessageFilePath(const QString& messageId,
                                            const QString& filePath) -> bool {
  QSqlQuery query(m_database);
  query.prepare("UPDATE messages SET content = ? WHERE message_id = ?");
  query.addBindValue(filePath.toUtf8());
  query.addBindValue(messageId);

  return query.exec();
}
