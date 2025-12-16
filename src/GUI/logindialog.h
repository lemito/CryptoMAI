#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <grpcpp/grpcpp.h>

#include <QDialog>
#include <QMessageBox>
#include <memory>

#include "proto/chat.grpc.pb.h"
#include "proto/chat.pb.h"
#include "sessionmanager.h"
#include "utils.hpp"

namespace Ui {
class LoginDialog;
}

class LoginDialog : public QDialog {
  Q_OBJECT

 public:
  explicit LoginDialog(QWidget* parent = nullptr);
  ~LoginDialog();

  [[nodiscard]] auto getUsername() const -> QString { return m_username; }
  [[nodiscard]] auto getSessionToken() const -> QString {
    return m_sessionToken;
  }

 signals:
  void loginSuccess(const QString& username, const QString& token);
  void rejected();

 private slots:
  void onLoginButton_clicked();
  void onRegisterButton_clicked();
  void checkCredentials();
  void onRejected() { emit rejected(); }

 private:
  Ui::LoginDialog* ui;
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
