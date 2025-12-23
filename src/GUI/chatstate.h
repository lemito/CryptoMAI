#ifndef CHATSTATE_H
#define CHATSTATE_H

#include <QObject>
#include <QVariantList>

class ChatState : public QObject {
  Q_OBJECT
  Q_PROPERTY(
      bool hasSelectedChat READ hasSelectedChat NOTIFY hasSelectedChatChanged)
  Q_PROPERTY(int messageCount READ messageCount NOTIFY messageCountChanged)
  Q_PROPERTY(
      QVariantList messageList READ messageList NOTIFY messageListChanged)

 public:
  explicit ChatState(QObject* parent = nullptr);

  [[nodiscard]] auto hasSelectedChat() const -> bool;
  [[nodiscard]] auto messageCount() const -> int;
  [[nodiscard]] auto messageList() const -> QVariantList;

  void updateState(bool hasChat, int count, const QVariantList& messages);

 signals:
  void hasSelectedChatChanged();
  void messageCountChanged();
  void messageListChanged();

 private:
  bool m_hasSelectedChat;
  int m_messageCount;
  QVariantList m_messageList;
};

#endif  // CHATSTATE_H
