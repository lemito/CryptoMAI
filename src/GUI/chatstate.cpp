#include "chatstate.h"

ChatState::ChatState(QObject* parent)
    : QObject(parent), m_hasSelectedChat(false), m_messageCount(0) {}

auto ChatState::hasSelectedChat() const -> bool { return m_hasSelectedChat; }

auto ChatState::messageCount() const -> int { return m_messageCount; }

auto ChatState::messageList() const -> QVariantList { return m_messageList; }

void ChatState::updateState(bool hasChat, int count,
                            const QVariantList& messages) {
  if (m_hasSelectedChat != hasChat) {
    m_hasSelectedChat = hasChat;
    emit hasSelectedChatChanged();
  }

  if (m_messageCount != count) {
    m_messageCount = count;
    emit messageCountChanged();
  }

  if (m_messageList != messages) {
    m_messageList = messages;
    emit messageListChanged();
  }
}
