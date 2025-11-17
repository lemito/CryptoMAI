#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "contactsdialog.h"
#include "logindialog.h"

#include <memory>
#include <grpcpp/grpcpp.h>
#include "proto/chat.pb.h"
#include "proto/chat.grpc.pb.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

 public slots:
  void onLoginSuccess(const QString& username, const QString& token);
  void onLogout();

 private:
  std::unique_ptr<chat::AuthService::Stub> authStub_;
  Ui::MainWindow *ui;
  std::unique_ptr<ContactsDialog> contactsDialog;
  SessionManager* m_sessionManager;
  QLabel *m_userLabel;
  QPushButton *m_logoutButton;

  void setupUserInterface();
  void updateUserInfo();

 private slots:
  void showContactsDialog();
  void on_userStatusButton_clicked();
  void on_contactsButton_clicked();
};
#endif  // MAINWINDOW_H
