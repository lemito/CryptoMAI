#include "mainwindow.h"

#include <QCloseEvent>
#include <QTimer>

#include "cypher/SymmetricAlgorithms/cypher.hpp"
#include "src/GUI/ui_mainwindow.h"
#include "utils.hpp"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      choiceDialog(nullptr),
      createChatDialog(nullptr),
      joinChatDialog(nullptr),
      m_dbManager(DatabaseManager::instance()),
      contactsDialog(new ContactsDialog(this)) {
  ui->setupUi(this);
  setAttribute(Qt::WA_DeleteOnClose, false);

  qApp->setStyleSheet(
      "QMessageBox QLabel { color: black; } QText { color: black; }");

  auto channel = grpc::CreateChannel("localhost:50051",
                                     grpc::InsecureChannelCredentials());
  authStub_ = chat::AuthService::NewStub(channel);
  chatStub_ = chat::ChatService::NewStub(channel);

  chat_stream_client_ = std::make_unique<ChatStreamClient>(chatStub_.get());

  connect(ui->newChatButton, &QPushButton::clicked, this,
          &MainWindow::onNewChatClicked);

  connect(ui->actionShowContacts, &QAction::triggered, this,
          &MainWindow::showContactsDialog);

  connect(ui->contactsButton, &QPushButton::clicked, this,
          &MainWindow::onContactsButton_clicked);

  connect(ui->userStatusButton, &QPushButton::clicked, this,
          &MainWindow::onUserStatusButton_clicked);

  connect(chat_stream_client_.get(), &ChatStreamClient::chatReceived, this,
          &MainWindow::onChatReceived);
  connect(chat_stream_client_.get(), &ChatStreamClient::streamError, this,
          &MainWindow::onStreamError);
  // connect(chat_stream_client_.get(), &ChatStreamClient::streamStatusChanged,
  //         this, &MainWindow::onStreamStatusChanged);

  if ((m_dbManager != nullptr) && !m_dbManager->init()) {
    qDebug() << "запрос инициализации бд";
    QMessageBox::critical(this, "Ошибка БД", "Не удалось создать БД");
  } else {
    // TODO
    qDebug() << "чёт загрузилось";
  }

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      {}, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);

  if (SessionManager::instance().isLoggedIn()) {
    updateUserInfo();
    startChatStream();
  }
}

void MainWindow::closeEvent(QCloseEvent* event) {
  stopChatStream();

  if (contactsDialog) {
    contactsDialog->stopAllThreads();
    contactsDialog->close();
  }
  if (SessionManager::instance().isLoggedIn()) {
    int result = QMessageBox::question(
        this, "Выход", "Закрыть приложение или остаться в системе?", "Закрыть",
        "Свернуть");
    if (result == 0) {
      qApp->quit();
    } else {
      event->ignore();
      this->hide();
      return;
    }
  }

  event->accept();
}

MainWindow::~MainWindow() {
  if (chat_stream_client_) {
    chat_stream_client_->stopStream();
  }

  delete ui;
}

void MainWindow::onContactsButton_clicked() { showContactsDialog(); }

void MainWindow::showContactsDialog() {
  if (!contactsDialog) {
    contactsDialog = std::make_unique<ContactsDialog>(this);
  }
  contactsDialog->show();
  contactsDialog->raise();
  contactsDialog->activateWindow();
}

void MainWindow::onChatReceived(const QString& chatId) {
  qDebug() << "Новый чат - ID:" << chatId;
  ui->chatsList->addItem(" (" + chatId + ")");
}

void MainWindow::onStreamError(const QString& error) {
  qCritical() << "ошибка:" << error;
  QMessageBox::warning(
      this, "Ошибка подключения",
      QString("Ошибка получения чатов: %1\nПопытка переподключения...")
          .arg(error));

  QTimer::singleShot(5000, this, &MainWindow::startChatStream);
}

// void MainWindow::onStreamStatusChanged(bool connected) {
//   qDebug() << "статус:" << (connected ? "connected" : "disconnected");
// }

void MainWindow::startChatStream() {
  if (SessionManager::instance().sessionToken().isEmpty()) {
    return;
  }

  if (chat_stream_client_->isStreaming()) {
    return;
  }

  qDebug() << "поток списка чатов начат...";
  chat_stream_client_->startStream();
}

void MainWindow::stopChatStream() {
  static bool stopping = false;
  if (stopping) {
    return;
  }

  stopping = true;
  qDebug() << "остановка потока получения чатов";

  if (chat_stream_client_) {
    chat_stream_client_->stopStream();
  }

  stopping = false;
}

void MainWindow::onLoginSuccess(const QString& username, const QString& token) {
  Q_UNUSED(username)
  Q_UNUSED(token)

  updateUserInfo();
  startChatStream();
}

void MainWindow::onLogout() {
  qDebug() << "выход";

  QMessageBox::information(this, "Выход", "Вы вышли из системы");

  stopChatStream();

  if (contactsDialog) {
    contactsDialog->stopAllThreads();
    contactsDialog->close();
    contactsDialog.reset();
  }

  chatKeys.clear();

  QString token = SessionManager::instance().sessionToken();
  if (!token.isEmpty()) {
    try {
      chat::LogoutRequest request;
      request.set_session_token(token.toStdString());

      grpc::ClientContext context;
      chat::CommonResponse response;

      grpc::Status status = authStub_->Logout(&context, request, &response);

      if (status.ok() && response.success()) {
        qDebug() << "Выход выполнен на сервере";
      } else {
        qCritical() << "Ошибка при выходе(grpc): "
                    << (status.ok() ? response.message().c_str()
                                    : status.error_message().c_str());
      }
    } catch (const std::exception& e) {
      qCritical() << "Ошибка при выходе: " << e.what();
    }
  }

  SessionManager::instance().clearSession();

  this->hide();
}

void MainWindow::onUserStatusButton_clicked() {
  if (SessionManager::instance().isLoggedIn()) {
    int result =
        QMessageBox::question(this, "Выход", "Вы уверены, что хотите выйти?",
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
        "}");

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
        "}");
  }
}

auto convertAlgorithm(int algorithm) -> chat::EncryptionAlgorithm {
  switch (algorithm) {
    case 0:
      return chat::LOKI97;
    case 1:
    default:
      return chat::RC6;
  }
}

auto convertMode(int mode) -> chat::EncryptionMode {
  switch (mode) {
    case 0:
      return chat::ECB;
    case 1:
      return chat::CBC;
    case 2:
      return chat::PCBC;
    case 3:
      return chat::CFB;
    case 4:
      return chat::OFB;
    case 5:
      return chat::CTR;
    case 6:
      return chat::RANDOM_DELTA;
    default:
      return chat::CBC;
  }
}

auto convertPadding(int padding) -> chat::PaddingMode {
  switch (padding) {
    case 0:
      return chat::ZEROS;
    case 1:
      return chat::ANSI_X923;
    case 2:
      return chat::PKCS7;
    case 3:
      return chat::ISO10126;
    default:
      return chat::PKCS7;
  }
}

void MainWindow::onNewChatClicked() {
  if (choiceDialog == nullptr) {
    choiceDialog = new ChoiceDialog(this);
    connect(choiceDialog, &ChoiceDialog::createChatRequested, this,
            &MainWindow::onCreateChatRequested);
    connect(choiceDialog, &ChoiceDialog::joinChatRequested, this,
            &MainWindow::onJoinChatRequested);
  }
  choiceDialog->exec();
}

void MainWindow::onCreateChatRequested() {
  if (createChatDialog == nullptr) {
    createChatDialog = new CreateChatDialog(this);
  }

  if (createChatDialog->exec() == QDialog::Accepted) {
    handleCreateChat(
        createChatDialog->getContactUsername(),
        createChatDialog->getAlgorithm(), createChatDialog->getMode(),
        createChatDialog->getPadding(), createChatDialog->getIV(),
        createChatDialog->getPrime(), createChatDialog->getGenerator(),
        createChatDialog->getPublicKey());
  }
}

void MainWindow::onJoinChatRequested() {
  if (joinChatDialog == nullptr) {
    joinChatDialog = new JoinChatDialog(this);
  }

  if (joinChatDialog->exec() == QDialog::Accepted) {
    handleJoinChat(joinChatDialog->getChatId(), joinChatDialog->getPrime(),
                   joinChatDialog->getGenerator(),
                   joinChatDialog->getPublicKey());
  }
}

void MainWindow::handleCreateChat(const QString& contact, int algorithm,
                                  int mode, int padding, const QByteArray& iv,
                                  const QByteArray& prime,
                                  const QByteArray& generator,
                                  const QByteArray& publicKey) {
  QString algorithmStr;
  switch (algorithm) {
    case 0:
      algorithmStr = "LOKI97";
      break;
    case 1:
      algorithmStr = "RC6";
      break;
    default:
      algorithmStr = "RC6";
  }

  QString modeStr;
  switch (mode) {
    case 0:
      modeStr = "ECB";
      break;
    case 1:
      modeStr = "CBC";
      break;
    case 2:
      modeStr = "PCBC";
      break;
    case 3:
      modeStr = "CFB";
      break;
    case 4:
      modeStr = "OFB";
      break;
    case 5:
      modeStr = "CTR";
      break;
    case 6:
      modeStr = "RANDOM_DELTA";
      break;
    default:
      modeStr = "CBC";
  }

  QString paddingStr;
  switch (padding) {
    case 0:
      paddingStr = "ZEROS";
      break;
    case 1:
      paddingStr = "ANSIX923";
      break;
    case 2:
      paddingStr = "PKCS7";
      break;
    case 3:
      paddingStr = "ISO10126";
      break;
    default:
      paddingStr = "PKCS7";
  }

  QString message = QString(
                        "Создание чата с пользователем: %1\n\n"
                        "Параметры шифрования:\n"
                        "• Алгоритм: %2\n"
                        "• Режим: %3\n"
                        "• Дополнение: %4\n"
                        "• IV: %5...\n\n"
                        "Ключ Диффи-Хеллмана сгенерированы")
                        .arg(contact)
                        .arg(algorithmStr)
                        .arg(modeStr)
                        .arg(paddingStr)
                        .arg(QString(iv.toHex()).left(16));

  QMessageBox::information(this, "🐱 Создание чата", message);

  try {
    chat::CreateChatRequest request;
    auto* encryptionParams = new chat::EncryptionParameters();
    auto* dhParams = new chat::DHParameters();

    request.set_contact_username(contact.toStdString());
    encryptionParams->set_algorithm(convertAlgorithm(algorithm));
    encryptionParams->set_mode(convertMode(mode));
    encryptionParams->set_padding(convertPadding(padding));
    encryptionParams->set_chat_iv(iv.toStdString());
    request.set_allocated_encryption_params(encryptionParams);

    dhParams->set_prime(prime.toStdString());
    dhParams->set_generator(generator.toStdString());
    dhParams->set_public_key(publicKey.toStdString());
    request.set_allocated_initiator_params(dhParams);

    grpc::ClientContext context;
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    } else {
      QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      return;
    }
    chat::ChatInfo response;

    grpc::Status status = chatStub_->CreateChat(&context, request, &response);

    if (status.ok()) {
      QString chatId = QString::fromStdString(response.chat_id());
      qDebug() << "Чат создан: " << chatId;

      ChatKeys keys;
      keys.sharedSecret = publicKey;
      keys.isInitialized = true;
      chatKeys[chatId] = keys;

      QMessageBox::information(
          this, "Успех",
          QString("Чат создан успешно!\nID чата: %1").arg(chatId));

    } else {
      qCritical() << "Ошибка: " << status.error_message().c_str();
      QMessageBox::critical(
          this, "Ошибка",
          QString("Не удалось создать чат: %1")
              .arg(QString::fromStdString(status.error_message())));
    }

  } catch (const std::exception& e) {
    qCritical() << "ошибка: " << e.what();
    QMessageBox::critical(
        this, "Ошибка",
        QString("Исключение при создании чата: %1").arg(e.what()));
  }
}

void MainWindow::handleJoinChat(const QString& chatId, const QByteArray& prime,
                                const QByteArray& generator,
                                const QByteArray& publicKey) {
  QString message =
      QString("Присоединение к чату %1\nDH параметры сгенерированы")
          .arg(chatId);

  QMessageBox::information(this, "🔗 Присоединение к чату", message);

  // TODO: grpc
  try {
    chat::JoinChatRequest request;
    request.set_chat_id(chatId.toStdString());

    auto* params = new chat::DHParameters();
    params->set_prime(prime.toStdString());
    params->set_generator(generator.toStdString());
    params->set_public_key(publicKey.toStdString());
    request.set_allocated_peer_params(params);

    grpc::ClientContext context;
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    } else {
      QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      return;
    }
    chat::CommonResponse response;
    grpc::Status status = chatStub_->JoinChat(&context, request, &response);

    if (status.ok() && response.success()) {
      qDebug() << "Чел вошел в чат";

      ChatKeys keys;
      keys.sharedSecret = publicKey;
      keys.isInitialized = true;
      chatKeys[chatId] = keys;

      QMessageBox::information(this, "Успех",
                               "Вы успешно присоединились к чату!");

    } else {
      std::string errorMsg =
          status.ok() ? response.message() : status.error_message();
      qCritical() << "Join Chat failed on server: " << errorMsg.c_str();
      QMessageBox::critical(this, "Ошибка",
                            QString("Не удалось присоединиться к чату: %1")
                                .arg(QString::fromStdString(errorMsg)));
    }

  } catch (const std::exception& e) {
    qCritical() << "Exception in JoinChat: " << e.what();
    QMessageBox::critical(
        this, "Ошибка",
        QString("Исключение при присоединении к чату: %1").arg(e.what()));
  }
}
