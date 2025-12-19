#include "chatmanager.h"

ChatManager::ChatManager(QObject* parent)
    : QObject(parent),
      m_qmlContext(nullptr),
      m_dbManager(nullptr),
      m_chatState(new ChatState(this)) {}

void ChatManager::setQmlContext(QQmlContext* context) {
  m_qmlContext = context;
  if (m_qmlContext != nullptr) {
    m_qmlContext->setContextProperty("chatState", m_chatState);
  }
}

void ChatManager::setDatabaseManager(DatabaseManager* dbManager) {
  m_dbManager = dbManager;
}

void ChatManager::loadChatHistory(const QString& chatId) {
  if (m_dbManager == nullptr) {
    qCritical() << "ChatManager: DatabaseManager null";
    return;
  }

  auto messages = m_dbManager->getChatMessages(chatId);
  if (messages.empty()) {
    qCritical() << "ChatManager: Не удалось получить соо из БД";
    return;
  }

  QVariantList messageList;
  QString curUser = SessionManager::instance().username();

  for (const Message& message : messages) {
    QVariantMap msgMap;
    msgMap["sender"] = message.sender;
    msgMap["isOwn"] = (message.sender == curUser) || (message.sender == "me");
    msgMap["timestamp"] = message.timestamp.toString("hh:mm");
    msgMap["isFile"] = message.isFile;
    if (message.isFile) {
      msgMap["fileId"] = message.fileName;
      msgMap["fileName"] = message.originalFilename.isEmpty()
                               ? message.fileName
                               : message.originalFilename;
      msgMap["mimeType"] = message.mimeType;
      msgMap["fileSize"] = message.fileSize;
      msgMap["content"] = message.content == "" ? message.fileName : message.content;
      msgMap["messageId"] = message.messageId;
      msgMap["downloadProgress"] = -1;

      QString ext = message.originalFilename.split('.').last().toLower();
      QStringList imageExts = {"jpg", "jpeg", "png", "gif", "bmp", "webp"};
      if (imageExts.contains(ext)) {
        emit autoDownloadImage(message.fileName);
      }
    } else {
      msgMap["content"] = QString::fromUtf8(message.content);
    }
    messageList.append(msgMap);
  }

  m_currentChatId = chatId;

  m_chatState->updateState(!chatId.isEmpty(), messages.size(), messageList);

  qDebug() << "ChatManager: загружено" << messages.size()
           << "соо для чата:" << chatId;
}

void ChatManager::clearChat() {
  m_currentChatId.clear();
  m_chatState->updateState(false, 0, QVariantList());
}

void ChatManager::onChatSelected(const QString& chatId) {
  qDebug() << "ChatManager: onChatSelected called with chatId:" << chatId;

  if (chatId.isEmpty()) {
    clearChat();
    return;
  }

  m_currentChatId = chatId;
  loadChatHistory(chatId);
}

void ChatManager::onMessageSaved(const QString& messageId,
                                 const QString& chatId) {
  qDebug() << "ChatManager: соо в бд " << messageId << " " << chatId;
  qDebug() << "ChatManager: обновление чата:" << chatId;
  loadChatHistory(chatId);
}

void ChatManager::updateFileProgress(const QString& fileId, int progress) {
  m_fileProgressMap[fileId] = progress;
  if (m_currentChatId.isEmpty()) {
    return;
  }

  auto messages = m_dbManager->getChatMessages(m_currentChatId);
  QVariantList messageList;
  QString curUser = SessionManager::instance().username();

  for (const auto& message : messages) {
    QVariantMap msgMap;
    msgMap["sender"] = message.sender;
    msgMap["isOwn"] = (message.sender == curUser) || (message.sender == "me");
    msgMap["timestamp"] = message.timestamp.toString("hh:mm");
    msgMap["isFile"] = static_cast<bool>(message.isFile);
    if (message.isFile) {
      msgMap["fileId"] = message.fileName;
      msgMap["fileName"] = message.originalFilename.isEmpty()
                               ? message.fileName
                               : message.originalFilename;
      msgMap["mimeType"] = message.mimeType;
      msgMap["fileSize"] = message.fileSize;
      msgMap["content"] = message.fileName;
      msgMap["messageId"] = message.messageId;
      msgMap["downloadProgress"] =
          m_fileProgressMap.value(message.fileName, -1);
    } else {
      msgMap["content"] = QString::fromUtf8(message.content);
    }
    messageList.append(msgMap);
  }

  m_chatState->updateState(true, messages.size(), messageList);
}
