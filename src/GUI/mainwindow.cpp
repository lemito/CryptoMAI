#include "mainwindow.h"
#include <iostream>
#include "cypher/SymmetricAlgorithms/cypher.hpp"
#include "src/GUI/ui_mainwindow.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      contactsDialog(new ContactsDialog(this)) {
  ui->setupUi(this);

  auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
  authStub_ = chat::AuthService::NewStub(channel);


  connect(ui->actionShowContacts, &QAction::triggered, this,
          &MainWindow::showContactsDialog);

  connect(ui->contactsButton, &QPushButton::clicked,
          this, &MainWindow::on_contactsButton_clicked);

  connect(ui->userStatusButton, &QPushButton::clicked,
          this, &MainWindow::on_userStatusButton_clicked);

  connect(&SessionManager::instance(), &SessionManager::sessionChanged,
          this, &MainWindow::updateUserInfo);

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      {}, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);

  if (SessionManager::instance().isLoggedIn()) {
    updateUserInfo();
  }
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::on_contactsButton_clicked() {
  showContactsDialog();
}

void MainWindow::showContactsDialog() {
  if (!contactsDialog) {
    contactsDialog = std::make_unique<ContactsDialog>(this);
  }
  contactsDialog->show();
  contactsDialog->raise();
  contactsDialog->activateWindow();
}

void MainWindow::onLoginSuccess(const QString& username, const QString& token)
{
  Q_UNUSED(token)

  updateUserInfo();
}

void MainWindow::onLogout() {
  std::cout << "Logout started" << std::endl;

  if (contactsDialog) {
    contactsDialog->stopAllThreads();
    contactsDialog->close();
    contactsDialog.reset();
  }

  QString token = SessionManager::instance().sessionToken();

  if (!token.isEmpty()) {
    try {
      chat::LogoutRequest request;
      request.set_session_token(token.toStdString());

      grpc::ClientContext context;
      chat::CommonResponse response;

      grpc::Status status = authStub_->Logout(&context, request, &response);

      if (status.ok() && response.success()) {
        std::cout << "Logout successful on server" << std::endl;
      } else {
        std::cerr << "Logout failed on server: "
                  << (status.ok() ? response.message() : status.error_message())
                  << std::endl;
      }
    } catch (const std::exception& e) {
      std::cerr << "Exception during logout: " << e.what() << std::endl;
    }
  }

  SessionManager::instance().clearSession();

  std::cout << "Session cleared" << std::endl;

  QMessageBox::information(this, "Выход", "Вы вышли из системы");

  this->close();
}


void MainWindow::on_userStatusButton_clicked() {
  if (SessionManager::instance().isLoggedIn()) {
    int result = QMessageBox::question(this, "Выход",
                                       "Вы уверены, что хотите выйти?",
                                       QMessageBox::Yes | QMessageBox::No);

    if (result == QMessageBox::Yes) {
      onLogout();
    }
  } else {
    QMessageBox::information(this, "Вход",
                             "Для входа в систему используйте диалог входа");
  }
}

void MainWindow::updateUserInfo() {
  if (SessionManager::instance().isLoggedIn()) {
    QString username = SessionManager::instance().username();

    ui->userNameLabel->setText(username);

    if (!username.isEmpty()) {
      QString avatarText = username.left(1).toUpper();
      ui->userAvatarLabel->setText(avatarText);
    }

    ui->userStatusButton->setToolTip("Выйти из системы");
    ui->userStatusButton->setStyleSheet(
        "QPushButton { "
        "    background-color: #ef4444; "
        "    border-radius: 6px; "
        "    border: 2px solid #1e293b; "
        "} "
        "QPushButton:hover { "
        "    background-color: #dc2626; "
        "}"
        );

  } else {
    ui->userNameLabel->setText("Не авторизован");
    ui->userAvatarLabel->setText("?");

    ui->userStatusButton->setToolTip("Войти в систему");
    ui->userStatusButton->setStyleSheet(
        "QPushButton { "
        "    background-color: #4ade80; "
        "    border-radius: 6px; "
        "    border: 2px solid #1e293b; "
        "} "
        "QPushButton:hover { "
        "    background-color: #22c55e; "
        "}"
        );
  }
}
