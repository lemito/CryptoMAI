#ifndef CONTACTLISTITEM_H
#define CONTACTLISTITEM_H

#include <QWidget>

class QLabel;
class QPushButton;

class ContactListItem : public QWidget
{
  Q_OBJECT

 public:
  ContactListItem(const QString &username, const QString &status,
                  const QString &requestId, QWidget *parent = nullptr);

  [[nodiscard]] auto username() const -> QString { return m_username; }

 signals:
  void acceptRequest(const QString &requestId);
  void rejectRequest(const QString &requestId);
  void removeContact(const QString &username);

 private slots:
  void onAcceptClicked();
  void onRejectClicked();
  void onRemoveClicked();

 private:
  void setupUI();
  void updateAppearance();

  QString m_username;
  QString m_status;
  QString m_requestId;

  QLabel *m_avatarLabel;
  QLabel *m_nameLabel;
  QPushButton *m_acceptButton;
  QPushButton *m_rejectButton;
  QPushButton *m_removeButton;
};

#endif // CONTACTLISTITEM_H
