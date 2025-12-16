#ifndef CHATMANAGER_H
#define CHATMANAGER_H

#include <QObject>
#include <QQmlContext>
#include <QVariantList>

#include "chat_structs.h"
#include "chatstate.h"
#include "databasemanager.h"
#include "sessionmanager.h"

class ChatManager : public QObject {
  Q_OBJECT

 public:
  QString m_currentChatId{};

  explicit ChatManager(QObject* parent = nullptr);
  void setQmlContext(QQmlContext* context);
  void setDatabaseManager(DatabaseManager* dbManager);

 signals:
  void autoDownloadImage(const QString& fileId);

 public slots:
  void loadChatHistory(const QString& chatId);
  void clearChat();
  void onChatSelected(const QString& chatId);
  void onMessageSaved(const QString& messageId, const QString& chatId);
  void updateFileProgress(const QString& fileId, int progress);

 private:
  QQmlContext* m_qmlContext;
  DatabaseManager* m_dbManager;
  ChatState* m_chatState;
  QMap<QString, int> m_fileProgressMap;
};

#endif  // CHATMANAGER_H
