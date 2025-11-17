#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <QDialog>
#include <QMessageBox>
#include <memory>
#include <grpcpp/grpcpp.h>
#include "proto/chat.pb.h"
#include "proto/chat.grpc.pb.h"
#include "sessionmanager.h"

namespace Ui {
class LoginDialog;
}

class LoginDialog : public QDialog {
  Q_OBJECT

 public:
  explicit LoginDialog(QWidget *parent = nullptr);
  ~LoginDialog();

  QString getUsername() const { return m_username; }
  QString getSessionToken() const { return m_sessionToken; }

 signals:
  void loginSuccess(const QString& username, const QString& token);

 private slots:
  void on_loginButton_clicked();
  void on_registerButton_clicked();
  void checkCredentials();

 private:
  Ui::LoginDialog *ui;
  std::unique_ptr<chat::AuthService::Stub> auth_stub_;
  QString m_username;
  QString m_sessionToken;

  void setupGRPCChannel();
  void handleLoginResponse(const chat::AuthResponse& response);
  void handleRegisterResponse(const chat::CommonResponse& response);
  void showError(const QString& title, const QString& message);
  void showSuccess(const QString& title, const QString& message);
};

#endif  // LOGINDIALOG_H
