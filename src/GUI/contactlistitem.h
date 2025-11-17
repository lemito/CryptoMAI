#ifndef CONTACTLISTITEM_H
#define CONTACTLISTITEM_H

#include <QWidget>
#include <QLabel>
#include <QHBoxLayout>
#include <QPushButton>

class ContactListItem : public QWidget
{
  Q_OBJECT

 public:
  explicit ContactListItem(const QString &username, const QString &status,
                           const QString &requestId = "", QWidget *parent = nullptr);

  QString username() const { return m_username; }
  QString status() const { return m_status; }
  QString requestId() const { return m_requestId; }

 signals:
  void acceptRequest(const QString &requestId);
  void rejectRequest(const QString &requestId);
  void removeContact(const QString &username);
  void startChat(const QString &username);

 private slots:
  void onAcceptClicked();
  void onRejectClicked();
  void onRemoveClicked();
  void onChatClicked();

 private:
  QString m_username;
  QString m_status;
  QString m_requestId;

  QLabel *m_avatarLabel;
  QLabel *m_nameLabel;
  QLabel *m_statusLabel;
  QPushButton *m_acceptButton;
  QPushButton *m_rejectButton;
  QPushButton *m_removeButton;
  QPushButton *m_chatButton;

  void setupUI();
  void updateAppearance();
};

#endif // CONTACTLISTITEM_H
