#include "logindialog.h"
#include "src/GUI/ui_logindialog.h"
#include <QMessageBox>
#include <QPushButton>
#include <QLineEdit>
#include <thread>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::LoginDialog) {
  ui->setupUi(this);

  setWindowTitle("Вход | MeowChat");

  ui->usernameEdit->setPlaceholderText("Введите логин");
  ui->passwordEdit->setPlaceholderText("Введите пароль");
  ui->passwordEdit->setEchoMode(QLineEdit::Password);

  setupGRPCChannel();

  connect(ui->loginButton, &QPushButton::clicked, this,
          &LoginDialog::on_loginButton_clicked);
  connect(ui->registerButton, &QPushButton::clicked, this,
          &LoginDialog::on_registerButton_clicked);

  connect(ui->usernameEdit, &QLineEdit::returnPressed, this,
          &LoginDialog::on_loginButton_clicked);
  connect(ui->passwordEdit, &QLineEdit::returnPressed, this,
          &LoginDialog::on_loginButton_clicked);

  ui->usernameEdit->setFocus();
}

LoginDialog::~LoginDialog() {
  delete ui;
}

void LoginDialog::on_loginButton_clicked() {
  if (ui->loginButton->isEnabled()) {
    checkCredentials();
  }
}

void LoginDialog::on_registerButton_clicked() {
  if (!ui->registerButton->isEnabled()) {
    return;
  }

  const QString username = ui->usernameEdit->text().trimmed();
  const QString password = ui->passwordEdit->text();

  if (username.isEmpty() || password.isEmpty()) {
    showError("Ошибка", "Заполните все поля!");
    ui->usernameEdit->setFocus();
    return;
  }

  ui->loginButton->setEnabled(false);
  ui->registerButton->setEnabled(false);

  std::thread([this, username, password](){
    chat::RegisterRequest req;
    req.set_username(username.toStdString());
    req.set_password(password.toStdString());

    chat::CommonResponse response;
    ClientContext context;

    Status status = auth_stub_->Register(&context, req, &response);

    QMetaObject::invokeMethod(this, [this, status, response](){
      ui->loginButton->setEnabled(true);
      ui->registerButton->setEnabled(true);
      handleRegisterResponse(response);
    }, Qt::QueuedConnection);
  }).detach();
}

void LoginDialog::checkCredentials() {
  const QString username = ui->usernameEdit->text().trimmed();
  const QString password = ui->passwordEdit->text();

  if (username.isEmpty() || password.isEmpty()) {
    showError("Ошибка", "Заполните все поля!");
    ui->usernameEdit->setFocus();
    return;
  }

  ui->loginButton->setEnabled(false);
  ui->registerButton->setEnabled(false);

  std::thread([this, username, password]() {
    chat::LoginRequest request;
    request.set_username(username.toStdString());
    request.set_password(password.toStdString());

    chat::AuthResponse response;
    ClientContext context;

    Status status = auth_stub_->Login(&context, request, &response);

    QMetaObject::invokeMethod(this, [this, status, response]() {
      ui->loginButton->setEnabled(true);
      ui->registerButton->setEnabled(true);

      if (status.ok()) {
        handleLoginResponse(response);
      } else {
        showError("Ошибка соединения",
                  QString("Не удалось подключиться к серверу: %1")
                      .arg(QString::fromStdString(status.error_message())));
      }
    }, Qt::QueuedConnection);
  }).detach();
}

void LoginDialog::setupGRPCChannel(){
  auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
  this->auth_stub_ = chat::AuthService::NewStub(channel);
}

void LoginDialog::handleLoginResponse(const chat::AuthResponse& response) {
  if (response.success()) {
    m_sessionToken = QString::fromStdString(response.session_token());
    m_username = ui->usernameEdit->text().trimmed();

    SessionManager::instance().setSessionData(m_sessionToken, m_username);

    // showSuccess("Успех", "Добро пожаловать в MeowChat!");

    emit loginSuccess(m_username, m_sessionToken);
    accept();
  } else {
    showError("Ошибка входа",
              QString::fromStdString(response.message()));

    ui->passwordEdit->clear();
    ui->passwordEdit->setFocus();
  }
}

void LoginDialog::handleRegisterResponse(const chat::CommonResponse& response) {
  if (response.success()) {
    showSuccess("Успех",
                QString::fromStdString(response.message()));

    ui->passwordEdit->clear();
    ui->passwordEdit->setFocus();
  } else {
    showError("Ошибка регистрации",
              QString::fromStdString(response.message()));

    ui->passwordEdit->clear();
    ui->passwordEdit->setFocus();
  }
}

void LoginDialog::showError(const QString& title, const QString& message) {
  QMessageBox::critical(this, title, message);
}

void LoginDialog::showSuccess(const QString& title, const QString& message) {
  QMessageBox::information(this, title, message);
}
