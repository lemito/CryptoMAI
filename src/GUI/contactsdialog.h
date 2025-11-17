#ifndef CONTACTSDIALOG_H
#define CONTACTSDIALOG_H

#include <QDialog>
#include <memory>
#include <atomic>
#include <thread>
#include <grpcpp/grpcpp.h>
#include "proto/chat.grpc.pb.h"
#include "sessionmanager.h"
#include "contactlistitem.h"

namespace Ui {
class ContactsDialog;
}

struct ContactInfo {
  QString username;
  QString status;
  QString requestId;
};

class ContactsDialog : public QDialog
{
  Q_OBJECT

 public:
  explicit ContactsDialog(QWidget *parent = nullptr);
  ~ContactsDialog();

  void stopAllThreads();

 private slots:
  void on_closeButton_clicked();
  void on_addContactButton_clicked();
  void on_searchEdit_textChanged(const QString &text);
  void onAcceptRequest(const QString &requestId);
  void onRejectRequest(const QString &requestId);
  void onRemoveContact(const QString &username);
  void onStartChat(const QString &username);
  void onErrorOccurred(const QString& errorMessage);

 private:
  void setupGrpcChannel();
  void loadContacts();
  void addContact(const QString& username);
  void handleContactRequest(const QString& requestId, bool approve);
  void onContactsLoaded(const QList<ContactInfo>& contacts);
  void clearContactsList();
  void addHeaderToContactsList(const QString &headerText);
  void addContactToContactsList(const ContactInfo &contact);
  void handleGrpcError(const grpc::Status& status, const QString& operation);

  void startContactUpdates();
  void stopContactUpdates();
  void onContactUpdateReceived(const chat::ContactUpdate& update);

  Ui::ContactsDialog *ui;
  std::unique_ptr<chat::ContactService::Stub> contactsStub_;

  std::unique_ptr<grpc::ClientContext> contactUpdatesContext_;
  std::unique_ptr<grpc::ClientReader<chat::ContactUpdate>> contactUpdatesReader_;
  std::atomic<bool> stopUpdates_{false};
  std::thread updatesThread_;
};

#endif // CONTACTSDIALOG_H
