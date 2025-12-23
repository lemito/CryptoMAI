#include "mainwindow.h"

#include <QByteArray>
#include <QCloseEvent>
#include <QFileDialog>
#include <QQmlContext>
#include <QQueue>
#include <QRandomGenerator>
#include <QTimer>
#include <QVariant>
#include <cstddef>
#include <vector>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      m_userLabel(nullptr),
      m_logoutButton(nullptr),
      choiceDialog(nullptr),
      createChatDialog(nullptr),
      joinChatDialog(nullptr),
      messagesModel(nullptr),
      m_sessionManager(nullptr),
      m_dbManager(DatabaseManager::instance()),
      m_fileManager(FileUploadManager::instance()),
      m_chatManager(std::make_unique<ChatManager>(this)),
      chatThreadPool(nullptr) {
  ui->setupUi(this);
  setAttribute(Qt::WA_DeleteOnClose, false);

  this->chat = ui->chat;
  ui->userStatusButton->hide();

  constexpr auto style_sheet = R"(
        QMessageBox {
            background-color: white;
            border: 1px solid #ccc;
        }
        QMessageBox QLabel {
            color: black;
            padding: 10px;
        }
        QMessageBox QTextEdit {
            color: black;
            background-color: #f9f9f9;
        }
        QMessageBox QPushButton {
            background-color: #E0E0E0;
            color: black;
            border: 1px solid #aaa;
            border-radius: 4px;
            padding: 5px 12px;
            min-width: 80px;
        }
        QMessageBox QPushButton:hover {
            background-color: #D0D0D0;
        }
        QMessageBox QPushButton:pressed {
            background-color: #C0C0C0;
        }
    )";

  qApp->setStyleSheet(style_sheet);

  try {
    using namespace grpc;

    auto channel = CreateChannel(GRPC_URL, InsecureChannelCredentials());
    authStub_ = chat::AuthService::NewStub(channel);
    chatStub_ = chat::ChatService::NewStub(channel);
    messagingStub_ = chat::MessagingService::NewStub(channel);

    chat_stream_client_ = std::make_unique<ChatStreamClient>(chatStub_.get());

    message_stream_client_ = std::make_unique<MessageStreamClient>(
        messagingStub_.get(), m_dbManager);

    message_sender_ =
        std::make_unique<MessageSender>(messagingStub_.get(), m_dbManager);

    message_sender_->setEncryptCallback(
        [this](const QString& chatId, const QByteArray& data) -> QByteArray {
          return encryptMessage(chatId, data);
        });

    message_stream_client_->setDecryptCallback(
        [this](const QString& chatId, const QByteArray& data) -> QByteArray {
          return decryptMessage(chatId, data);
        });

    m_chatManager->setDatabaseManager(m_dbManager);
    m_chatManager->setQmlContext(chat->rootContext());

    m_fileManager.initialize(
        QString::fromStdString(MINIO_URL), QString::fromStdString(MINIO_USR),
        QString::fromStdString(MINIO_PASS), false, "us-east-1");

    auto setup_connections = [this]() -> void {
      connect(&m_fileManager, &FileUploadManager::downloadProgress, this,
              &MainWindow::onDownloadProgress);

      connect(&m_fileManager, &FileUploadManager::downloadFinished, this,
              &MainWindow::onDownloadFinished);

      connect(&m_fileManager, &FileUploadManager::downloadFailed, this,
              &MainWindow::onDownloadFailed);

      connect(ui->newChatButton, &QPushButton::clicked, this,
              &MainWindow::onNewChatClicked);

      connect(ui->actionShowContacts, &QAction::triggered, this,
              &MainWindow::showContactsDialog);

      connect(ui->contactsButton, &QPushButton::clicked, this,
              &MainWindow::onContactsButton_clicked);

      connect(ui->userStatusButton, &QPushButton::clicked, this,
              &MainWindow::onUserStatusButton_clicked);

      connect(ui->settingsButton, &QPushButton::clicked, this,
              &MainWindow::onChatSettingsButton_clicked);

      connect(ui->fileButton, &QPushButton::clicked, this,
              &MainWindow::onSendFileClicked);

      connect(ui->updateChatsButton, &QPushButton::clicked, this,
              [this]() -> void {
                this->manualSyncChats();
                // refreshChatsList();
                // initializeExistingChats();
              });

      connect(chat_stream_client_.get(), &ChatStreamClient::chatReceived, this,
              &MainWindow::onChatReceived);

      connect(chat_stream_client_.get(), &ChatStreamClient::streamError, this,
              &MainWindow::onStreamError);

      connect(message_stream_client_.get(),
              &MessageStreamClient::messageReceived, this,
              &MainWindow::onMessageReceived);

      connect(message_stream_client_.get(), &MessageStreamClient::streamError,
              this, &MainWindow::onMessageStreamError);

      connect(ui->sendButton, &QPushButton::clicked, this,
              &MainWindow::onSendMessageClicked);

      connect(message_stream_client_.get(), &MessageStreamClient::messageSaved,
              m_chatManager.get(), &ChatManager::onMessageSaved);

      connect(m_chatManager.get(), &ChatManager::autoDownloadImage, this,
              &MainWindow::downloadFile);

      connect(ui->chatsList, &QListWidget::itemClicked, this,
              [this](QListWidgetItem* item) -> void {
                if (auto chatId = item->data(Qt::UserRole); chatId.isValid()) {
                  const QString chatid = chatId.toString();
                  // if (!chatContexts.contains(chatid)) {
                  //   qCritical() << "чат выбирался, но контекста такого нет";
                  //   return;
                  // }

                  m_dbManager->markMessagesAsRead(chatid);

                  m_chatManager->onChatSelected(chatid);
                  const QString nameChat = item->text();
                  ui->chatNameLabel->setText(nameChat);

                  qDebug() << "Чат выбран:" << chatid;
                }
              });

      connect(ui->stickersButton, &QPushButton::clicked, this,
              &MainWindow::onStickersButtonClicked);
    };

    setup_connections();

    ui->messageInput->installEventFilter(this);

    chatThreadPool = new QThreadPool(this);
    chatThreadPool->setMaxThreadCount(4);

    connect(ui->actionAbout, &QAction::triggered, this, [this] {
      auto* aboutDialog = new QDialog(this);
      aboutDialog->setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
      aboutDialog->setAttribute(Qt::WA_DeleteOnClose);
      aboutDialog->setModal(true);
      aboutDialog->resize(500, 400);
      aboutDialog->setObjectName("aboutDialog");

      auto* quickWidget = new QQuickWidget(aboutDialog);
      quickWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
      quickWidget->setSource(QUrl("qrc:/dialogs/AboutDialog.qml"));
      quickWidget->setStyleSheet("background: transparent; border: none;");

      auto* mainLayout = new QVBoxLayout(aboutDialog);
      mainLayout->setContentsMargins(0, 0, 0, 0);
      mainLayout->addWidget(quickWidget);

      auto* closeButton = new QPushButton("✕", aboutDialog);
      closeButton->setFixedSize(30, 30);
      closeButton->setStyleSheet(R"(
        QPushButton {
            background-color: rgba(255, 255, 255, 150);
            border-radius: 15px;
            font-size: 16px;
            font-weight: bold;
            color: black;
        }
        QPushButton:hover {
            background-color: rgba(255, 255, 255, 200);
        }
    )");

      auto* topLayout = new QHBoxLayout();
      topLayout->setContentsMargins(5, 5, 5, 0);
      topLayout->addStretch();
      topLayout->addWidget(closeButton);

      safe_delete(mainLayout);
      mainLayout = new QVBoxLayout(aboutDialog);
      mainLayout->setContentsMargins(0, 0, 0, 0);
      mainLayout->addLayout(topLayout);
      mainLayout->addWidget(quickWidget);

      connect(closeButton, &QPushButton::clicked, aboutDialog, &QDialog::close);

      aboutDialog->show();
    });

    if ((m_dbManager != nullptr) && !m_dbManager->init()) {
      qDebug() << "Запрос инициализации БД";
      QMessageBox::critical(this, "Ошибка БД", "Не удалось создать БД");
    } else {
      qDebug() << "БД загружена успешно";
    }

    const auto& session = SessionManager::instance();
    if (session.isLoggedIn()) {
      updateUserInfo();
      startChatStream();
      refreshChatsList();

      if (message_stream_client_) {
        message_stream_client_->startStream();
      }

      initializeExistingChats();
    }

    {
      qDebug() << "ChatView.qml";
      chat->setSource(QUrl("qrc:/chat/ChatView.qml"));
      chat->rootContext()->setContextProperty("mainWindow", this);

      auto* ctx = chat->rootContext();
      ctx->setContextProperty("hasSelectedChat", false);
      ctx->setContextProperty("messageCount", 0);
      ctx->setContextProperty("messageList", QVariantList());

      m_chatManager->setQmlContext(ctx);
      m_chatManager->setDatabaseManager(m_dbManager);

      auto* rootObject = qobject_cast<QQuickItem*>(chat->rootObject());
      if (rootObject != nullptr) {
        connect(rootObject, SIGNAL(fileDownloadRequested(QString)), this,
                SLOT(downloadFile(QString)));
        qDebug() << "fileDownloadRequested <-> downloadFile";
      }
      qDebug() << "ChatView.qml done!";
    }

  } catch (const std::exception& e) {
    qCritical() << std::format("Ошибка в конструкторе MainWindow: {}", e.what())
                       .c_str();
  }
}

auto MainWindow::eventFilter(QObject* obj, QEvent* event) -> bool {
  if (obj == ui->messageInput && event->type() == QEvent::KeyPress) {
    auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
    if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) {
      if (keyEvent->modifiers() == Qt::NoModifier) {
        onSendMessageClicked();
        return true;
      }
    }
  }
  return QMainWindow::eventFilter(obj, event);
}

void MainWindow::closeEvent(QCloseEvent* event) {
  m_isDestroying = true;

  stopChatStream();

  if (contactsDialog) {
    contactsDialog->stopAllThreads();
    contactsDialog->close();
  }

  event->accept();
  qApp->quit();
}

MainWindow::~MainWindow() {
  m_isDestroying = true;

  stopChatStream();
  if (message_stream_client_) {
    message_stream_client_->stopStream();
  }

  if (chatThreadPool != nullptr) {
    chatThreadPool->waitForDone(5000);
    safe_delete(chatThreadPool);
  }

  {
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

        grpc::ClientContext ctx;
        chat::CommonResponse response;

        grpc::Status status = authStub_->Logout(&ctx, request, &response);

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

    qDebug() << "выход";
  }

  safe_delete(m_stickerPicker);
  safe_delete(ui);
}

void MainWindow::onContactsButton_clicked() { showContactsDialog(); }

void MainWindow::showContactsDialog() {
  try {
    contactsDialog = std::make_unique<ContactsDialog>(this);
    contactsDialog->show();
    contactsDialog->raise();
    contactsDialog->activateWindow();
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при открытии диалога контактов:" << e.what();
  }
}

void MainWindow::onChatReceived(
    const QString& chatId, const QString& partiName,
    const ::chat::DHParameters& peerParams,
    const ::chat::EncryptionParameters& algoParams) {
  qDebug() << "Получены параметры чата, запуск фоновой обработки:" << chatId;

  QtConcurrent::run(
      chatThreadPool,
      [this, chatId, partiName, peerParams, algoParams]() -> void {
        processChatInBackground(chatId, partiName, peerParams, algoParams);
      });
}

void MainWindow::processChatInBackground(
    const QString& chatId, const QString& partiName,
    const ::chat::DHParameters& peerParams,
    const ::chat::EncryptionParameters& algoParams) {
  if (m_isDestroying) {
    qDebug() << "MainWindow разрушается, пропускаем обработку чата:" << chatId;
    return;
  }

  qDebug() << "Обработка чата в фоновом потоке, ID:" << chatId;

  QMetaObject::invokeMethod(this, [this, chatId, partiName, peerParams,
                                   algoParams]() {
    Chat chat =
        m_dbManager->getChat(chatId, SessionManager::instance().username());

    if (chat.chatId.isEmpty()) {
      qWarning() << "Чат не найден в БД, создаём новый:" << chatId;

      const QString curName = SessionManager::instance().username();
      const QString chatName = curName + " | " + partiName;
      const QString algoName = QString::fromStdString(
          ::chat::EncryptionAlgorithm_Name(algoParams.algorithm()));
      const QString modeName = QString::fromStdString(
          ::chat::EncryptionMode_Name(algoParams.mode()));
      QString padName = QString::fromStdString(
          ::chat::PaddingMode_Name(algoParams.padding()));
      if (padName == "ANSI_X923") {
        // TODO(lemito): по хорошему, любое использование перевеода в строке параметров должно использовать PaddingMode_Name
        padName = QString("ANSIX923");
      }
      const QString IV =
          QByteArray::fromStdString(algoParams.chat_iv()).toHex().toUpper();

      const QString prime = QString::fromStdString(peerParams.prime());
      const QString generator = QString::fromStdString(peerParams.generator());
      const QString pkPeer = QString::fromStdString(peerParams.public_key());

      if (!m_dbManager->addChat(chatId, chatName, curName, algoName, modeName,
                                padName, IV, "", prime, generator, "", pkPeer,
                                false)) {
        QMessageBox::critical(this, "ошибка", "чат не смог сохраниться в БД");
        return;
      }

      {
        absl::MutexLock lock(&chatKeysMutex);
        ChatKeys keys;
        const auto dh = get_dh();
        keys.prime = BI(prime.toStdString());
        keys.generator = BI(generator.toStdString());
        keys.peerPublicKey = BI(pkPeer.toStdString());
        keys.myPrivateKey = dh.secret;
        keys.myPublicKey = dh.getPublicKey();
        keys.isInitialized = false;

        auto [it, inserted] = chatKeys.insert({chatId, std::move(keys)});
        if (inserted) {
          qDebug() << "Ключи чата добавлены для новой записи:" << chatId;
        }
      }

      qDebug() << "Запуск обмена DH параметрами для нового чата:" << chatId;
      exchangeDHParameters(chatId);
      refreshChatsList();
      return;
    }

    qDebug() << "Чат уже существует в БД:" << chatId;

    QString primeStr = QString::fromStdString(peerParams.prime());
    QString genStr = QString::fromStdString(peerParams.generator());
    QString peerPubKeyStr = QString::fromStdString(peerParams.public_key());
    QString ivStr =
        QByteArray::fromStdString(algoParams.chat_iv()).toHex().toUpper();
    // QString ivStr = QString::fromStdString(algoParams.chat_iv());

    m_dbManager->updateChatParams(chatId, primeStr, genStr, peerPubKeyStr,
                                  ivStr);

    {
      absl::MutexLock lock(&chatKeysMutex);
      auto it = chatKeys.find(chatId);

      if (it == chatKeys.end()) {
        const auto dh = get_dh();
        ChatKeys keys;
        keys.peerPublicKey = BI(peerPubKeyStr.toStdString());
        // keys.myPrivateKey = BI(0);
        // keys.myPublicKey = BI(0);
        keys.myPrivateKey = dh.secret;
        keys.myPublicKey = dh.getPublicKey();
        keys.isInitialized = false;
        chatKeys.insert({chatId, keys});
        qDebug() << "Структура ключей создана для существующего чата:"
                 << chatId;
      } else {
        it->second.peerPublicKey = BI(peerPubKeyStr.toStdString());
        qDebug() << "Публичный ключ собеседника обновлён для:" << chatId;
      }
    }

    qDebug() << "Запуск обмена DH параметрами для существующего чата:"
             << chatId;
    exchangeDHParameters(chatId);
  });
}

void MainWindow::onStreamError(const QString& error) {
  qCritical() << "ошибка:" << error;
  QMessageBox::warning(
      this, "Ошибка подключения",
      QString("Ошибка получения чатов: %1\nПопытка переподключения...")
          .arg(error));
}

void MainWindow::startChatStream() {
  try {
    if (SessionManager::instance().sessionToken().isEmpty()) {
      return;
    }

    if (chat_stream_client_->isStreaming()) {
      return;
    }

    qDebug() << "поток списка чатов начат...";
    chat_stream_client_->startStream();
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при запуске потока чатов:" << e.what();
  }
}

void MainWindow::stopChatStream() {
  try {
    static std::atomic<bool> stopping = false;
    if (stopping) {
      return;
    }

    stopping = true;
    qDebug() << "остановка потока получения чатов";

    if (chat_stream_client_) {
      chat_stream_client_->stopStream();
    }

    stopping = false;
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при остановке потока чатов:" << e.what();
  }
}

void MainWindow::onLoginSuccess(const QString& username, const QString& token) {
  Q_UNUSED(username)
  Q_UNUSED(token)

  reinitializeForNewUser();
  // updateUserInfo();
  // startChatStream();
}

void MainWindow::reinitializeForNewUser() {
  if (SessionManager::instance().isLoggedIn()) {
    message_sender_.reset();
    message_sender_ =
        std::make_unique<MessageSender>(messagingStub_.get(), m_dbManager);
    message_sender_->setEncryptCallback(
        [this](const QString& chatId, const QByteArray& data) -> QByteArray {
          return encryptMessage(chatId, data);
        });

    updateUserInfo();
    startChatStream();
    refreshChatsList();

    if (message_stream_client_) {
      message_stream_client_->startStream();
    }

    initializeExistingChats();
  }
}
// void MainWindow::reinitializeForNewUser() {
//   if (SessionManager::instance().isLoggedIn()) {
//     updateUserInfo();
//     startChatStream();
//     refreshChatsList();

//     if (message_stream_client_) {
//       message_stream_client_->startStream();
//     }

//     initializeExistingChats();
//   }
// }

void MainWindow::onLogout() {
  qDebug() << "выход";

  stopChatStream();
  if (message_stream_client_) {
    message_stream_client_->stopStream();
  }

  if (chatThreadPool != nullptr) {
    chatThreadPool->waitForDone();
  }

  {
    absl::MutexLock lock(&chatKeysMutex);
    chatKeys.clear();
  }

  {
    absl::MutexLock lock(&chatContextMutex_);
    chatContexts.clear();
  }

  {
    absl::MutexLock lock(&activeDHMutex_);
    activeDHExchanges_.clear();
  }

  ui->chatsList->clear();
  ui->chatNameLabel->clear();
  ui->messageInput->clear();
  m_chatManager->clearChat();

  if (contactsDialog) {
    contactsDialog->stopAllThreads();
    contactsDialog->close();
    contactsDialog.reset();
  }

  if (m_syncTimer != nullptr) {
    m_syncTimer->stop();
  }

  QString token = SessionManager::instance().sessionToken();
  if (!token.isEmpty()) {
    try {
      if (m_dbManager != nullptr) {
        QVector<Chat> chats =
            m_dbManager->getAllChats(SessionManager::instance().username());
        for (const Chat& chat : chats) {
          m_dbManager->updateChatParams(chat.chatId, chat.prime, chat.generator,
                                        "", chat.iv);
        }
      }

      chat::LogoutRequest request;
      request.set_session_token(token.toStdString());
      grpc::ClientContext ctx;
      chat::CommonResponse response;
      grpc::Status status = authStub_->Logout(&ctx, request, &response);

      if (status.ok() && response.success()) {
        qDebug() << "Выход выполнен на сервере";
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
    const BaseChatDialog* asBaseChat =
        dynamic_cast<BaseChatDialog*>(createChatDialog);
    handleCreateChat(createChatDialog->getContactUsername(),
                     createChatDialog->getAlgorithm(),
                     createChatDialog->getMode(),
                     createChatDialog->getPadding(), createChatDialog->getIV(),
                     asBaseChat->dhPrime, asBaseChat->dhGenerator,
                     asBaseChat->dhPublicKey, asBaseChat->dhPrivateKey);
    refreshChatsList();
  }
}

void MainWindow::onJoinChatRequested() {
  if (joinChatDialog == nullptr) {
    joinChatDialog = new JoinChatDialog(this);
  }

  if (joinChatDialog->exec() == QDialog::Accepted) {
    chat::GetChatDHParamsRequest request;
    QString chatId = joinChatDialog->getChatId();
    request.set_chat_id(chatId.toStdString());

    grpc::ClientContext ctx;
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    } else {
      QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      return;
    }
    chat::GetChatDHParamsResponse response;

    grpc::Status status = chatStub_->GetChatDHParams(&ctx, request, &response);

    if (status.ok() && response.success()) {
      const BI prime(response.initiator_params().prime());
      const BI generator(response.initiator_params().generator());

      const BaseChatDialog* asBaseChat =
          dynamic_cast<BaseChatDialog*>(joinChatDialog);
      handleJoinChat(chatId, prime, generator, asBaseChat->dhPublicKey,
                     asBaseChat->dhPrivateKey);
      refreshChatsList();
    } else {
      qCritical() << "Ошибка: " << status.error_message().c_str();
      QMessageBox::critical(
          this, "Ошибка",
          QString("Не удалось подключиться к чату: %1")
              .arg(QString::fromStdString(status.error_message())));
    }
  }
}

void MainWindow::handleCreateChat(const QString& contact, int algorithm,
                                  int mode, int padding, const QByteArray& iv,
                                  const BI& prime, const BI& generator,
                                  const BI& publicKey, const BI& privateKey) {
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

    dhParams->set_prime(prime.str());
    dhParams->set_generator(generator.str());
    dhParams->set_public_key(publicKey.str());
    request.set_allocated_initiator_params(dhParams);

    grpc::ClientContext ctx;
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    } else {
      QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      return;
    }
    chat::ChatInfo response;

    grpc::Status status = chatStub_->CreateChat(&ctx, request, &response);

    if (status.ok()) {
      QString chatId = QString::fromStdString(response.chat_id());
      QString username = SessionManager::instance().username();
      QString chatName = username + " | " + contact;
      auto stat = m_dbManager->addChat(
          chatId, chatName, username, algorithmStr, modeStr, paddingStr,
          iv.toHex().toUpper(), username, QString::fromStdString(prime.str()),
          QString::fromStdString(generator.str()),
          QString::fromStdString(publicKey.str()), QString(), false);
      if (!stat) {
        QMessageBox::critical(this, "Ошибка", "Не удалось добавить чат в БД");
        return;
      }
      qDebug() << "Чат создан: " << chatId;

      ChatKeys keys;
      keys.prime = prime;
      keys.generator = generator;
      keys.myPrivateKey = privateKey;
      keys.myPublicKey = publicKey;
      keys.peerPublicKey = BI(0);
      keys.isInitialized = false;
      chatKeys.emplace(chatId, keys);

      exchangeDHParameters(chatId);

      QMessageBox::information(
          this, "Успех",
          QString("Чат создан успешно!\nID чата: %1\nДождитесь подключения "
                  "второго участника и обмена ключами")
              .arg(chatId));

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

void MainWindow::handleJoinChat(const QString& chatId, const BI& prime,
                                const BI& generator, const BI& publicKey,
                                const BI& privateKey) {
  QString message =
      QString("Присоединение к чату %1\nDH параметры сгенерированы")
          .arg(chatId);

  QMessageBox::information(this, "🔗 Присоединение к чату", message);

  try {
    chat::JoinChatRequest request;
    request.set_chat_id(chatId.toStdString());

    auto* params = new chat::DHParameters();
    params->set_prime(prime.str());
    params->set_generator(generator.str());
    params->set_public_key(publicKey.str());
    request.set_allocated_peer_params(params);

    grpc::ClientContext ctx;
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    } else {
      QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      return;
    }
    chat::CommonResponse response;
    grpc::Status status = chatStub_->JoinChat(&ctx, request, &response);

    if (status.ok() && response.success()) {
      qDebug() << "Чел вошел в чат";

      auto it = chatKeys.find(chatId);
      if (it != chatKeys.end()) {
        it->second.myPrivateKey = privateKey;
        it->second.myPublicKey = publicKey;
      }

      QMessageBox::information(
          this, "Успех",
          "Вы успешно присоединились к чату!\nОжидайте уведомления о чате...");
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

void MainWindow::onMessageReceived(const chat::EncryptedChunk& chunk) {
  try {
    auto chunkCopy = std::make_shared<chat::EncryptedChunk>(chunk);

    QtConcurrent::run(chatThreadPool, [this, chunkCopy]() -> void {
      try {
        if (m_isDestroying) {
          return;
        }

        const auto& metadata = chunkCopy->metadata();
        QString messageId = QString::fromStdString(metadata.message_id());
        QString chatId = QString::fromStdString(metadata.chat_id());
        QString fileId = QString::fromStdString(metadata.file_id());
        QByteArray content =
            QByteArray::fromStdString(chunkCopy->encrypted_content());

        int chunkIndex = metadata.chunk_index();
        int totalChunks = metadata.total_chunks();
        bool isFile = metadata.is_file();

        if (m_chatManager) {
          QMetaObject::invokeMethod(this, [this, chatId]() -> void {
            if (getcurChatId() == chatId) {
              m_chatManager->loadChatHistory(chatId);
            }
          });
        }

      } catch (const std::exception& e) {
        qCritical() << "Ошибка обработки сообщения:" << e.what();
      }
    });
  } catch (const std::exception& e) {
    qCritical() << "Ошибка в onMessageReceived:" << e.what();
  }
}

void MainWindow::onMessageStreamError(const QString& error) {
  try {
    qCritical() << "MainWindow: onMessageStreamError:" << error;
    QTimer::singleShot(5000, this, [this]() {
      try {
        if (message_stream_client_ && SessionManager::instance().isLoggedIn()) {
          message_stream_client_->startStream();
        }
      } catch (const std::exception& e) {
        qCritical() << "Ошибка при переподключении потока сообщений:"
                    << e.what();
      }
    });
  } catch (const std::exception& e) {
    qCritical() << "Ошибка в onMessageStreamError:" << e.what();
  }
}

void MainWindow::onSendMessageClicked() {
  try {
    const QString curChatId = getcurChatId();
    const QByteArray originalData = ui->messageInput->toPlainText().toUtf8();
    {
      absl::MutexLock lock(&chatContextMutex_);
      if (!chatContexts.contains(curChatId)) {
        qCritical() << "чат выбирался, но контекста такого нет";
        QMessageBox::warning(
            this, "Security",
            "Обмен ключами не произошел, нельзя отослать соо :(");
        return;
      }
    }

    if (originalData.size() > 0 && !curChatId.isEmpty()) {
      message_sender_->sendMessage(curChatId, originalData, false);
      ui->messageInput->clear();

      if (m_chatManager) {
        m_chatManager->loadChatHistory(curChatId);
      }
    } else {
      QMessageBox::warning(this, "Ошибка", "Введите сообщение и выберите чат");
    }
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при отправке сообщения:" << e.what();
    QMessageBox::critical(this, "Ошибка", "Не удалось отправить сообщение");
  }
}

void MainWindow::onSendFileClicked() {
  qDebug() << "onSendFileClicked начало";
  QString curChatId = getcurChatId();
  qDebug() << "curChatId:" << curChatId;
  if (curChatId.isEmpty()) {
    QMessageBox::warning(this, "Ошибка", "Выберите чат для отправки файла.");
    return;
  }
  QString filePath =
      QFileDialog::getOpenFileName(this, "Выберите файл для отправки");
  qDebug() << "Выбран файл:" << filePath;
  if (filePath.isEmpty()) {
    qDebug() << "пустой путь == отмена";
    return;
  }
  QFileInfo fileInfo(filePath);
  QString originalFileName = fileInfo.fileName();
  qint64 originalFileSize = fileInfo.size();
  qDebug() << "Имя:" << originalFileName << "Размер:" << originalFileSize;

  QString fileId = QUuid::createUuid().toString(QUuid::WithoutBraces);
  qDebug() << "fileId:" << fileId;
  QString tempEncryptedFilePath = QDir::temp().filePath(fileId + "_encrypted");
  qDebug() << "tempEncryptedFilePath:" << tempEncryptedFilePath;

  QtConcurrent::run(chatThreadPool, [this, curChatId, filePath, fileId,
                                     tempEncryptedFilePath, originalFileName,
                                     originalFileSize]() {
    {
      absl::MutexLock lock(&chatContextMutex_);
      auto it = chatContexts.find(curChatId);
      if (it != chatContexts.end()) {
        try {
          qDebug() << "Начало шифрования";
          it->second.encrypt(tempEncryptedFilePath.toStdString(),
                             filePath.toStdString());
          qDebug() << "Файл зашифрован:" << tempEncryptedFilePath;
        } catch (const std::exception& e) {
          qCritical() << "Ошибка шифрования:" << e.what();
          QMetaObject::invokeMethod(this, [this, e, tempEncryptedFilePath]() {
            QMessageBox::critical(
                this, "Ошибка",
                QString("Ошибка шифрования файла: %1").arg(e.what()));
          });
          QFile::remove(tempEncryptedFilePath);
          return;
        }
      } else {
        qCritical() << "Контекст шифрования не найден для чата:" << curChatId;
        QMetaObject::invokeMethod(this, [this]() {
          QMessageBox::critical(this, "Ошибка",
                                "Контекст шифрования не найден для чата.");
        });
        return;
      }
    }

    QMetaObject::invokeMethod(this, [this, curChatId, fileId, originalFileName,
                                     originalFileSize, tempEncryptedFilePath,
                                     filePath]() {
      qDebug() << "Подключение сигналов uploadFinished и uploadFailed";
      auto* conn = new QMetaObject::Connection();
      *conn = connect(
          &m_fileManager, &FileUploadManager::uploadFinished, this,
          [this, curChatId, fileId, originalFileName, originalFileSize,
           tempEncryptedFilePath, filePath, conn](const QString& objectName) {
            if (m_isDestroying) {
              disconnect(*conn);
              if (conn != nullptr) {
                delete conn;
              }
              return;
            }
            qDebug() << "uploadFinished сигнал получен для:" << objectName;
            if (objectName == fileId) {
              qDebug() << "Отправка метаданных файла";
              bool pic = isImageFileByExtension(originalFileName);
              message_sender_->sendFileInfo(
                  curChatId, fileId, originalFileName, originalFileSize,
                  "application/octet-stream", true, pic ? filePath : "");
              QFile::remove(tempEncryptedFilePath);
              qDebug() << "Временный файл удален";
              QMessageBox::information(this, "Файл отправлен",
                                       QString("Файл '%1' успешно отправлен.")
                                           .arg(originalFileName));
              if (m_chatManager) {
                m_chatManager->loadChatHistory(curChatId);
              }
              disconnect(*conn);
              if (conn != nullptr) {
                delete conn;
              }
            }
          });

      connect(&m_fileManager, &FileUploadManager::uploadFailed, this,
              [fileId, this](const QString& objectName, const QString& error) {
                if (objectName == fileId) {
                  QMessageBox::critical(this, "uploadFailed", error);
                  qCritical()
                      << "uploadFailed:" << objectName << "error:" << error;
                }
              });

      qDebug() << "Вызов uploadFile для bucket-name-meow-chat";
      m_fileManager.uploadFile("bucket-name-meow-chat", fileId,
                               tempEncryptedFilePath);
      qDebug() << "uploadFile вызван для:" << originalFileName;
    });
  });
  // m_chatManager->loadChatHistory();
}

auto MainWindow::getcurChatId() const -> QString {
  if (m_chatManager == nullptr) {
    qWarning() << "getcurChatId: m_chatManager не инициализирован";
    return "";
  }
  return m_chatManager->m_currentChatId;
}

void MainWindow::refreshChatsList() {
  try {
    ui->chatsList->clear();

    if (m_dbManager == nullptr) {
      qWarning() << "refreshChatsList: DatabaseManager не инициализирован";
      return;
    }
    if (m_chatManager == nullptr) {
      qWarning() << "refreshChatsList: m_chatManager не инициализирован";
      return;
    }

    QVector<Chat> chats =
        m_dbManager->getAllChats(SessionManager::instance().username());
    for (const Chat& chat : chats) {
      int unreadCount = m_dbManager->getUnreadCount(chat.chatId);
      QString displayText;
      if (unreadCount > 0) {
        displayText = QString("💬 %1 (%2)").arg(chat.name).arg(unreadCount);
      } else {
        displayText = QString("💬 %1").arg(chat.name);
      }
      auto* item = new QListWidgetItem(displayText);
      item->setData(Qt::UserRole, chat.chatId);
      if (unreadCount > 0) {
        QFont font = item->font();
        font.setBold(true);
        item->setFont(font);
      }

      ui->chatsList->addItem(item);
    }

    m_chatManager->clearChat();
    qDebug() << "Загружено чатов:" << chats.size();
  } catch (const std::exception& e) {
    qCritical() << "Ошибка в refreshChatsList:" << e.what();
  }
}

void MainWindow::initializeExistingChats() {
  if (m_dbManager == nullptr) {
    qWarning() << "initializeExistingChats: DatabaseManager не инициализирован";
    return;
  }

  QVector<Chat> chats =
      m_dbManager->getAllChats(SessionManager::instance().username());
  qDebug() << "Инициализация существующих чатов:" << chats.size();

  for (const Chat& chat : chats) {
    absl::MutexLock lock(&chatKeysMutex);
    if (chatKeys.find(chat.chatId) == chatKeys.end()) {
      const auto dh = get_dh();
      ChatKeys keys;
      keys.prime = BI(chat.prime.toStdString());
      keys.generator = BI(chat.generator.toStdString());
      keys.peerPublicKey = BI(0);
      keys.myPrivateKey = dh.secret;
      keys.myPublicKey = dh.getPublicKey();
      keys.isInitialized = false;

      chatKeys.insert({chat.chatId, keys});
      qDebug() << "Структура ключей подготовлена для чата:" << chat.chatId;
    }
  }

  for (const Chat& chat : chats) {
    int randomDelay = 500 + (QRandomGenerator::global()->bounded(2000));
    QTimer::singleShot(
        randomDelay, this, [this, chatId = chat.chatId]() -> void {
          {
            absl::MutexLock lock(&chatContextMutex_);
            if (chatContexts.contains(chatId)) {
              qDebug() << "Контекст уже существует для чата:" << chatId;
            }
          }
          qDebug() << "Запуск обмена ключами для существующего чата:" << chatId;
          exchangeDHParameters(chatId);
        });
  }
  // auto chatQueue = std::make_shared<QQueue<QString>>();
  // for (const Chat& chat : chats) {
  //   chatQueue->enqueue(chat.chatId);
  // }

  // auto* timer = new QTimer(this);
  // connect(timer, &QTimer::timeout, this, [this, timer, chatQueue]() {
  //   if (chatQueue->empty()) {
  //     timer->stop();
  //     timer->deleteLater();
  //     return;
  //   }
  //   auto chatId = chatQueue->dequeue();
  //   exchangeDHParameters(chatId);
  // });
  // timer->start(500);
}

void MainWindow::onChatSettingsButton_clicked() {
  QString curChatId = getcurChatId();

  if (curChatId.isEmpty()) {
    QMessageBox::information(this, "Настройки чата",
                             "Выберите чат для просмотра настроек.");
    return;
  }

  if (m_dbManager == nullptr) {
    QMessageBox::critical(this, "Ошибка", "База данных недоступна");
    return;
  }

  Chat chatInfo =
      m_dbManager->getChat(curChatId, SessionManager::instance().username());

  if (chatInfo.chatId.isEmpty()) {
    QMessageBox::warning(this, "Ошибка",
                         "Не удалось загрузить информацию о чате.");
    return;
  }

  QDialog settingsDialog(this);
  settingsDialog.setWindowTitle("Настройки чата");
  settingsDialog.setMinimumWidth(400);
  settingsDialog.setMinimumHeight(350);

  auto* mainLayout = new QVBoxLayout(&settingsDialog);

  auto* chatInfoGroup = new QGroupBox("Информация о чате", &settingsDialog);
  auto* infoLayout = new QFormLayout(chatInfoGroup);

  auto* chatNameEdit = new QLineEdit(chatInfo.name, chatInfoGroup);
  chatNameEdit->setReadOnly(true);
  infoLayout->addRow("Название чата:", chatNameEdit);

  auto* chatIdEdit = new QLineEdit(chatInfo.chatId, chatInfoGroup);
  chatIdEdit->setReadOnly(true);
  infoLayout->addRow("ID чата:", chatIdEdit);

  mainLayout->addWidget(chatInfoGroup);

  auto* encryptionGroup =
      new QGroupBox("Настройки шифрования", &settingsDialog);
  auto* encryptionLayout = new QFormLayout(encryptionGroup);

  auto* algorithmEdit = new QLineEdit(chatInfo.algorithm, encryptionGroup);
  algorithmEdit->setReadOnly(true);
  encryptionLayout->addRow("Алгоритм:", algorithmEdit);

  auto* modeEdit = new QLineEdit(chatInfo.mode, encryptionGroup);
  modeEdit->setReadOnly(true);
  encryptionLayout->addRow("Режим:", modeEdit);

  auto* paddingEdit = new QLineEdit(chatInfo.padding, encryptionGroup);
  paddingEdit->setReadOnly(true);
  encryptionLayout->addRow("Дополнение:", paddingEdit);

  if (!chatInfo.iv.isEmpty()) {
    auto* ivEdit = new QLineEdit(chatInfo.iv.left(16) + "...", encryptionGroup);
    ivEdit->setReadOnly(true);
    encryptionLayout->addRow("IV (первые 16 символов):", ivEdit);
  }

  mainLayout->addWidget(encryptionGroup);

  auto* participantsGroup = new QGroupBox("Участники чата", &settingsDialog);
  auto* participantsLayout = new QVBoxLayout(participantsGroup);

  auto* participantsList = new QListWidget(participantsGroup);

  QString currentUser = SessionManager::instance().username();
  if (!currentUser.isEmpty()) {
    auto* currentUserItem = new QListWidgetItem(
        QString("👤 %1 (Вы)").arg(currentUser), participantsList);
    currentUserItem->setFlags(currentUserItem->flags() & ~Qt::ItemIsEnabled);
  }

  QStringList nameParts = chatInfo.name.split(" | ");
  for (const QString& part : nameParts) {
    if (part != currentUser) {
      auto* participantItem =
          new QListWidgetItem(QString("👤 %1").arg(part), participantsList);
      participantItem->setData(Qt::UserRole, part);
    }
  }

  if (participantsList->count() <= 1) {
    participantsList->addItem("Участники не загружены");
  }

  participantsLayout->addWidget(participantsList);
  mainLayout->addWidget(participantsGroup);

  auto* actionsGroup = new QGroupBox("Действия", &settingsDialog);
  auto* actionsLayout = new QVBoxLayout(actionsGroup);

  auto* leaveButton = new QPushButton("Покинуть чат", actionsGroup);
  auto* closeButton = new QPushButton("Закрыть чат", actionsGroup);

  leaveButton->setStyleSheet("background-color: #ff9800; color: white;");
  closeButton->setStyleSheet("background-color: #f44336; color: white;");

  actionsLayout->addWidget(leaveButton);
  actionsLayout->addWidget(closeButton);
  mainLayout->addWidget(actionsGroup);

  QObject::connect(
      leaveButton, &QPushButton::clicked, [this, curChatId, &settingsDialog]() {
        int result =
            QMessageBox::question(&settingsDialog, "Покинуть чат",
                                  "Вы уверены, что хотите покинуть этот чат?",
                                  QMessageBox::Yes | QMessageBox::No);

        if (result == QMessageBox::Yes) {
          try {
            ::chat::CloseChatRequest req;
            req.set_chat_id(curChatId.toStdString());

            grpc::ClientContext ctx;
            QString token = SessionManager::instance().sessionToken();
            if (!token.isEmpty()) {
              ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
            } else {
              QMessageBox::critical(this, "Ошибка",
                                    "Необходимо войти в систему");
              return;
            }
            chat::CommonResponse response;
            grpc::Status status = chatStub_->LeaveChat(&ctx, req, &response);

            if (status.ok() && response.success()) {
              qDebug() << SessionManager::instance().username() << " ливнул";
              auto stat = m_dbManager->removeChat(
                  curChatId, SessionManager::instance().username());
              if (!stat) {
                std::string errorMsg = "БД";
                qCritical() << "Ошибка: " << errorMsg.c_str();
                // QMessageBox::critical(
                //     this, "Ошибка",
                //     QString("Не удалось ливнуть к чату: %1")
                //         .arg(QString::fromStdString(errorMsg)));
                settingsDialog.reject();
              }
              {
                absl::MutexLock lock(&chatKeysMutex);
                chatKeys.erase(curChatId);
              }
              {
                absl::MutexLock lock(&chatContextMutex_);
                chatContexts.erase(curChatId);
              }
              {
                absl::MutexLock lock(&activeDHMutex_);
                activeDHExchanges_.erase(curChatId.toStdString());
              }
              qDebug() << "Чел вышел из чата";
              QMessageBox::information(&settingsDialog, "Успех", "Чат закрыт");
              settingsDialog.accept();
              refreshChatsList();
            } else {
              std::string errorMsg =
                  status.ok() ? response.message() : status.error_message();
              qCritical() << "Ошибка: " << errorMsg.c_str();
              QMessageBox::critical(this, "Ошибка",
                                    QString("Не удалось покинуть к чату: %1")
                                        .arg(QString::fromStdString(errorMsg)));
              settingsDialog.reject();
            }
          } catch (const std::exception& e) {
            QMessageBox::critical(
                &settingsDialog, "Ошибка",
                QString("Ошибка при выходе из чата: %1").arg(e.what()));
          }
        }
      });

  QObject::connect(
      closeButton, &QPushButton::clicked, [this, curChatId, &settingsDialog]() {
        int result =
            QMessageBox::question(&settingsDialog, "Закрыть чат",
                                  "Вы уверены, что хотите закрыть этот чат? "
                                  "Это действие необратимо.",
                                  QMessageBox::Yes | QMessageBox::No);

        if (result == QMessageBox::Yes) {
          try {
            ::chat::CloseChatRequest req;
            req.set_chat_id(curChatId.toStdString());

            grpc::ClientContext ctx;
            QString token = SessionManager::instance().sessionToken();
            if (!token.isEmpty()) {
              ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
            } else {
              QMessageBox::critical(this, "Ошибка",
                                    "Необходимо войти в систему");
              return;
            }
            chat::CommonResponse response;
            grpc::Status status = chatStub_->CloseChat(&ctx, req, &response);

            if (status.ok() && response.success()) {
              auto stat = m_dbManager->removeChat(
                  curChatId, SessionManager::instance().username());
              if (!stat) {
                std::string errorMsg = "БД";
                qCritical() << "Ошибка: " << errorMsg.c_str();
                // QMessageBox::critical(
                //     this, "Ошибка",
                //     QString("Не удалось покинуть к чату: %1")
                //         .arg(QString::fromStdString(errorMsg)));
                settingsDialog.reject();
              }
              {
                absl::MutexLock lock(&chatKeysMutex);
                chatKeys.erase(curChatId);
              }
              {
                absl::MutexLock lock(&chatContextMutex_);
                chatContexts.erase(curChatId);
              }
              {
                absl::MutexLock lock(&activeDHMutex_);
                activeDHExchanges_.erase(curChatId.toStdString());
              }
              qDebug() << "Чел вышел успешно в чат";
              QMessageBox::information(&settingsDialog, "Успех", "Чат закрыт");
              settingsDialog.accept();
              refreshChatsList();
            } else {
              std::string errorMsg =
                  status.ok() ? response.message() : status.error_message();
              qCritical() << "Ошибка: " << errorMsg.c_str();
              QMessageBox::critical(this, "Ошибка",
                                    QString("Не удалось покинуть к чату: %1")
                                        .arg(QString::fromStdString(errorMsg)));
              settingsDialog.reject();
            }
          } catch (const std::exception& e) {
            QMessageBox::critical(
                &settingsDialog, "Ошибка",
                QString("Ошибка при закрытии чата: %1").arg(e.what()));
          }
        }
      });

  auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &settingsDialog);
  mainLayout->addWidget(buttonBox);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, &settingsDialog,
                   &QDialog::accept);
  QObject::connect(buttonBox, &QDialogButtonBox::rejected, &settingsDialog,
                   &QDialog::reject);

  settingsDialog.exec();
}

auto MainWindow::createContext(const Chat& chatInfo, const BI& symmetricKey)
    -> meow::cypher::symm::SymmetricCypherContext {
  std::shared_ptr<meow::cypher::symm::ISymmetricCypher> algo;
  if (chatInfo.algorithm == "RC6") {
    algo = std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
        std::make_shared<meow::cypher::symm::RC6::RC6>());
  } else if (chatInfo.algorithm == "LOKI97") {
    algo = std::static_pointer_cast<meow::cypher::symm::ISymmetricCypher>(
        std::make_shared<meow::cypher::symm::LOKI97::LOKI97>());
  } else {
    qCritical() << "нет такого алгоритма " << chatInfo.algorithm;
    throw std::runtime_error("нет такого алгоритма " +
                             chatInfo.algorithm.toStdString());
  }

  meow::cypher::symm::encryptionMode mode;
  qDebug() << "encryptionMode - " << chatInfo.mode;
  if (chatInfo.mode == "ECB") {
    mode = meow::cypher::symm::encryptionMode::ECB;
  } else if (chatInfo.mode == "CBC") {
    mode = meow::cypher::symm::encryptionMode::CBC;
  } else if (chatInfo.mode == "PCBC") {
    mode = meow::cypher::symm::encryptionMode::PCBC;
  } else if (chatInfo.mode == "CFB") {
    mode = meow::cypher::symm::encryptionMode::CFB;
  } else if (chatInfo.mode == "OFB") {
    mode = meow::cypher::symm::encryptionMode::OFB;
  } else if (chatInfo.mode == "CTR") {
    mode = meow::cypher::symm::encryptionMode::CTR;
  } else if (chatInfo.mode == "RANDOM_DELTA") {
    mode = meow::cypher::symm::encryptionMode::RandomDelta;
  } else {
    mode = meow::cypher::symm::encryptionMode::CBC;
  }

  meow::cypher::symm::paddingMode pad;
  qDebug() << "paddingMode - " << chatInfo.padding;
  if (chatInfo.padding == "ZEROS") {
    pad = meow::cypher::symm::paddingMode::Zeros;
  } else if (chatInfo.padding == "ANSIX923") {
    pad = meow::cypher::symm::paddingMode::AnsiX923;
  } else if (chatInfo.padding == "PKCS7") {
    pad = meow::cypher::symm::paddingMode::PKCS7;
  } else if (chatInfo.padding == "ISO10126") {
    pad = meow::cypher::symm::paddingMode::ISO10126;
  } else {
    pad = meow::cypher::symm::paddingMode::PKCS7;
  }

  const auto IV_hex = QByteArray::fromHex(chatInfo.iv.toUtf8());
  std::vector<std::byte> IV(
      reinterpret_cast<const std::byte*>(IV_hex.constData()),
      reinterpret_cast<const std::byte*>(IV_hex.constData() + IV_hex.size()));

  // из числа будет делать ключ нужной мне длинны
  auto keyDerivation = [&]() -> std::vector<std::byte> {
    std::vector<std::byte> key(32, std::byte{0});

    size_t size = (mpz_sizeinbase(symmetricKey.backend().data(), 2) + 7) / 8;

    if (size == 0) {
      qCritical() << "Ошибка: ключ нулевой";
      return key;
    }

    std::vector<unsigned char> buf(size);
    mpz_export(buf.data(), &size, 1, 1, 0, 0, symmetricKey.backend().data());

    size_t copySize = std::min(size, size_t(32));
    size_t offset = 32 - copySize;

    std::memcpy(reinterpret_cast<unsigned char*>(key.data()) + offset,
                buf.data(), copySize);

    QString hex;
    for (auto b : key) {
      hex += QString("%1").arg(static_cast<int>(b), 2, 16, QChar('0'));
    }
    qDebug() << "Ключ (hex):" << hex;

    return key;
  };

  const auto key = keyDerivation();

  try {
    meow::cypher::symm::SymmetricCypherContext ctx =
        meow::cypher::symm::SymmetricCypherContext(key, mode, pad, IV, BI(42));
    ctx.setAlgo(algo);

    return ctx;
  } catch (const std::exception& e) {
    qCritical() << "создание контекста ОШИБКА: " << e.what();
    throw;
  }
}

auto MainWindow::encryptMessage(const QString& chatId,
                                const QByteArray& plaintext) -> QByteArray {
  absl::MutexLock lock(&chatContextMutex_);
  auto it = chatContexts.find(chatId);
  if (it != chatContexts.end()) {
    std::vector<std::byte> plaintextVec(
        reinterpret_cast<const std::byte*>(plaintext.constData()),
        reinterpret_cast<const std::byte*>(plaintext.constData() +
                                           plaintext.size()));
    std::vector<std::byte> encrypted;
    try {
      it->second.encrypt(encrypted, plaintextVec);
      return QByteArray(reinterpret_cast<const char*>(encrypted.data()),
                        encrypted.size());
    } catch (const std::exception& e) {
      qCritical() << "Ошибка шифрования:" << e.what();
    }
  } else {
    qCritical() << "Контекст шифрования не найден для чата:" << chatId;
  }
  return plaintext;
}

auto MainWindow::decryptMessage(const QString& chatId,
                                const QByteArray& ciphertext) -> QByteArray {
  absl::MutexLock lock(&chatContextMutex_);
  auto it = chatContexts.find(chatId);
  if (it != chatContexts.end()) {
    std::vector<std::byte> ciphertextVec(
        reinterpret_cast<const std::byte*>(ciphertext.constData()),
        reinterpret_cast<const std::byte*>(ciphertext.constData() +
                                           ciphertext.size()));
    std::vector<std::byte> decrypted;
    try {
      it->second.decrypt(decrypted, ciphertextVec);
      return QByteArray(reinterpret_cast<const char*>(decrypted.data()),
                        decrypted.size());
    } catch (const std::exception& e) {
      qCritical() << "Ошибка расшифровки:" << e.what();
    }
  } else {
    qCritical() << "Контекст расшифровки не найден для чата:" << chatId;
  }
  return ciphertext;
}

void MainWindow::computeSharedSecretAndInitializeContext(
    const QString& chatId) {
  absl::MutexLock lock(&chatKeysMutex);

  auto it = chatKeys.find(chatId);
  if (it == chatKeys.end()) {
    qCritical() << "Ошибка: ключи не найдены для чата:" << chatId;
    return;
  }

  ChatKeys& keys = it->second;

  if (keys.myPrivateKey.str().empty()) {
    qCritical() << "Ошибка: мой приватный ключ пуст для" << chatId;
    return;
  }

  if (keys.peerPublicKey.str().empty()) {
    qCritical() << "Ошибка: публичный ключ собеседника пуст для" << chatId;
    return;
  }

  if (keys.isInitialized) {
    qDebug() << "Контекст уже инициализирован для" << chatId;
    return;
  }

  try {
    BI sharedSecret = meow::math::modPow(keys.peerPublicKey, keys.myPrivateKey,
                                         BI(DH_STANDART_P_str_hex));

    keys.symmetricKey = sharedSecret;
    keys.isInitialized = true;

    qDebug() << "Общий секрет вычислен для" << chatId;

    Chat chatInfo =
        m_dbManager->getChat(chatId, SessionManager::instance().username());
    if (chatInfo.chatId.isEmpty()) {
      qCritical() << "Ошибка: чат не найден в БД:" << chatId;
      return;
    }

    try {
      auto context = createContext(chatInfo, sharedSecret);
      {
        absl::MutexLock ctx_lock(&chatContextMutex_);
        chatContexts.emplace(chatId, std::move(context));
      }
      qDebug() << "Контекст инициализирован для чата:" << chatId
               << "Secret key:" << sharedSecret.str().c_str();
    } catch (const std::exception& e) {
      qCritical() << "Ошибка при создании контекста шифрования:" << e.what();
      keys.isInitialized = false;
    }

  } catch (const std::exception& e) {
    qCritical() << "Ошибка при вычислении DH секрета:" << e.what();
  }
}

void MainWindow::exchangeDHParameters(const QString& chatId) {
  if (m_isDestroying) {
    return;
  }
  qDebug() << "Начало обмена DH параметрами для чата:" << chatId;

  {
    absl::MutexLock lock(&activeDHMutex_);
    if (activeDHExchanges_[chatId.toStdString()]) {
      qDebug() << "DH обмен уже в процессе для" << chatId;
      return;
    }
    activeDHExchanges_[chatId.toStdString()] = true;
  }

  QtConcurrent::run(chatThreadPool, [this, chatId]() -> void {
    if (m_isDestroying) {
      qDebug() << "MainWindow разрушается, пропускаем DH обмен для:" << chatId;
      {
        absl::MutexLock lock(&activeDHMutex_);
        activeDHExchanges_[chatId.toStdString()] = false;
      }
      return;
    }

    BI prime, generator;
    BI myPrivateKey, myPublicKey;
    QString token;

    {
      absl::MutexLock lock(&chatKeysMutex);
      auto it = chatKeys.find(chatId);

      if (it == chatKeys.end()) {
        qCritical() << "Ошибка: ключи для чата не инициализированы:" << chatId;
        const auto [prime_val, generator_val] =
            get_dh_params(DH_STANDART_P_str_hex, DH_STANDART_G_str_hex);
        const auto dh = get_dh();
        ChatKeys key;
        key.prime = prime_val;
        key.generator = generator_val;
        key.myPrivateKey = dh.secret;
        key.myPublicKey = dh.getPublicKey();
        key.peerPublicKey = BI(0);
        key.isInitialized = false;

        it = chatKeys.insert({chatId, std::move(key)}).first;
      }

      prime = it->second.prime;
      generator = it->second.generator;
      myPrivateKey = it->second.myPrivateKey;
      myPublicKey = it->second.myPublicKey;

      if (it->second.myPrivateKey.str().empty() ||
          it->second.myPublicKey.str().empty()) {
        const auto dh = get_dh();
        it->second.myPrivateKey = dh.secret;
        it->second.myPublicKey = dh.getPublicKey();
        qDebug() << "Ключи DH сгенерированы для активного обмена:" << chatId;
      }
    }

    QMetaObject::invokeMethod(
        this, [&token]() { token = SessionManager::instance().sessionToken(); },
        Qt::BlockingQueuedConnection);

    if (token.isEmpty()) {
      QMetaObject::invokeMethod(this, [this]() {
        QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
      });
      {
        absl::MutexLock lock(&activeDHMutex_);
        activeDHExchanges_[chatId.toStdString()] = false;
      }
      return;
    }

    try {
      chat::DHParametersExchange request;
      request.set_chat_id(chatId.toStdString());

      auto* dhParametersProto = new chat::DHParameters();
      dhParametersProto->set_prime(prime.str());
      dhParametersProto->set_generator(generator.str());
      dhParametersProto->set_public_key(myPublicKey.str());
      request.set_allocated_parameters(dhParametersProto);

      auto context = std::make_shared<grpc::ClientContext>();
      context->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());

      std::chrono::system_clock::time_point deadline =
          std::chrono::system_clock::now() + std::chrono::minutes(10);
      context->set_deadline(deadline);

      auto stream = chatStub_->ExchangeDHParametersStream(context.get());

      if (!stream->Write(request)) {
        qCritical() << "Ошибка отправки DH параметров для чата:" << chatId;
        {
          absl::MutexLock lock(&activeDHMutex_);
          activeDHExchanges_[chatId.toStdString()] = false;
        }
        return;
      }

      qDebug() << "DH параметры отправлены, ждем ответа для чата:" << chatId;

      chat::DHParametersResponse response;
      while (stream->Read(&response)) {
        if (response.has_peer_params()) {
          QString peerPubKey =
              QString::fromStdString(response.peer_params().public_key());
          qDebug() << "Получен публичный ключ собеседника для" << chatId;

          {
            absl::MutexLock lock(&chatKeysMutex);
            auto it = chatKeys.find(chatId);
            if (it != chatKeys.end()) {
              it->second.peerPublicKey = BI(peerPubKey.toStdString());
              if (!it->second.myPrivateKey.str().empty()) {
                QMetaObject::invokeMethod(this, [this, chatId]() {
                  computeSharedSecretAndInitializeContext(chatId);
                });
              }
            }
          }
        } else if (response.exchange_complete()) {
          qDebug() << "Обмен DH завершен сервером для чата:" << chatId;
          break;
        }
      }

      stream->Finish();

      {
        absl::MutexLock lock(&activeDHMutex_);
        activeDHExchanges_[chatId.toStdString()] = false;
      }

    } catch (const std::exception& e) {
      qCritical() << "Исключение при обмене DH параметрами:" << e.what();
      {
        absl::MutexLock lock(&activeDHMutex_);
        activeDHExchanges_[chatId.toStdString()] = false;
      }
    }
  });
}

bool MainWindow::isImageFileByExtension(const QString& fileName) {
  if (fileName.isEmpty()) {
    return false;
  }

  QString extension = QFileInfo(fileName).suffix().toLower();
  static const QStringList imageExtensions = {
      "png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico", "svg"};

  return imageExtensions.contains(extension);
}

QString MainWindow::getDownloadsPath() {
  return QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
}

void MainWindow::onDownloadProgress(const QString& objectName,
                                    qint64 bytesReceived, qint64 bytesTotal) {
  if (bytesTotal > 0) {
    int percent = (bytesReceived * 100) / bytesTotal;
    if (m_chatManager) {
      m_chatManager->updateFileProgress(objectName, percent);
    }
  }
}

void MainWindow::onDownloadFailed(const QString& objectName,
                                  const QString& errorMessage) {
  qCritical() << QString("Не удалось загрузить '%1':\n%2")
                     .arg(objectName)
                     .arg(errorMessage);

  QMessageBox::critical(this, "Ошибка загрузки",
                        QString("Не удалось загрузить '%1':\n%2")
                            .arg(objectName)
                            .arg(errorMessage));
}

QString MainWindow::formatBytes(qint64 bytes) {
  const char* units[] = {"Б", "КБ", "МБ", "ГБ", "ТБ"};
  int unitIndex = 0;
  double size = bytes;

  while (size >= 1024 && unitIndex < 4) {
    size /= 1024;
    unitIndex++;
  }

  return QString("%1 %2").arg(size, 0, 'f', 1).arg(units[unitIndex]);
}

void MainWindow::downloadFile(const QString& fileId) {
  try {
    if (fileId.isEmpty()) {
      qCritical() << "Попытка скачать файл с пустым ID.";
      return;
    }

    Message fileMessage = m_dbManager->getFileMessageByFileId(fileId);
    if (fileMessage.messageId.isEmpty()) {
      qCritical() << "Сообщение о файле не найдено в БД для fileId:" << fileId;
      QMessageBox::critical(this, "Ошибка", "Информация о файле не найдена.");
      return;
    }

    qDebug() << "downloadFile";

    if (!fileMessage.content.isEmpty()) {
      return;
    }

    qDebug() << "meow";

    m_currentDownload = fileId;
    QString tempEncryptedFilePath =
        QDir::temp().filePath(fileId + "_encrypted");

    qDebug() << "скачивание файла:" << fileId << "в" << tempEncryptedFilePath;
    m_fileManager.downloadFile("bucket-name-meow-chat", fileId,
                               tempEncryptedFilePath);
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при скачивании файла:" << e.what();
    QMessageBox::critical(this, "Ошибка", "Не удалось скачать файл");
  }
}

void MainWindow::onDownloadFinished(const QString& objectName,
                                    const QString& filePath) {
  if (m_chatManager) {
    m_chatManager->updateFileProgress(objectName, -1);
  }

  qDebug() << "Зашифрованный файл скачан в:" << filePath;

  Message fileMessage = m_dbManager->getFileMessageByFileId(objectName);
  if (fileMessage.messageId.isEmpty()) {
    qCritical() << "Сообщение о файле не найдено в БД для objectName:"
                << objectName;
    QFile::remove(filePath);
    return;
  }

  QString defaultName = fileMessage.originalFilename.isEmpty()
                            ? fileMessage.fileName
                            : fileMessage.originalFilename;
  QString savePath;
  if (isImageFileByExtension(fileMessage.originalFilename)) {
    QDir downloadsDir(getDownloadsPath());
    savePath = downloadsDir.absoluteFilePath(fileMessage.fileName);

    qDebug() << "Изображение сохранено в:" << savePath;
  } else {
    savePath = QFileDialog::getSaveFileName(this, "Сохранить файл",
                                            fileMessage.originalFilename);
    if (savePath.isEmpty()) {
      qDebug() << "Сохранение файла отменено пользователем.";
      QFile::remove(filePath);
      return;
    }
  }

  QtConcurrent::run(chatThreadPool, [this, fileMessage, filePath, savePath]() {
    qDebug() << "Фоновое дешифрование началось";
    {
      absl::MutexLock lock(&chatContextMutex_);
      auto it = chatContexts.find(fileMessage.chatId);
      if (it != chatContexts.end()) {
        try {
          it->second.decrypt(savePath.toStdString(), filePath.toStdString());

          QMetaObject::invokeMethod(this, [this, fileMessage, savePath]() {
            if (m_dbManager->updateMessageFilePath(fileMessage.messageId,
                                                   savePath)) {
              qDebug() << "Путь к расшифрованному файлу обновлен в БД";
              if (m_chatManager) {
                m_chatManager->loadChatHistory(fileMessage.chatId);
              }
            }
            // QDesktopServices::openUrl(
            //     QUrl::fromLocalFile(QFileInfo(savePath).path()));
          });

          QFile::remove(filePath);
        } catch (const std::exception& e) {
          qCritical() << "Ошибка дешифрования файла:" << e.what();
          QFile::remove(filePath);
        }
      } else {
        qCritical() << "Контекст шифрования не найден для чата:"
                    << fileMessage.chatId;
        QFile::remove(filePath);
      }
    }
  });
}

void MainWindow::onStickersButtonClicked() {
  try {
    qDebug() << "Кнопка стикеров нажата";

    if (!m_stickerPicker) {
      qDebug() << "Создание диалога стикеров";
      m_stickerPicker = new StickerPickerDialog();
      connect(m_stickerPicker, &StickerPickerDialog::stickerSelected, this,
              &MainWindow::onStickerSelected);
    }

    if (m_stickerPicker->isVisible()) {
      qDebug() << "Скрытие диалога стикеров";
      m_stickerPicker->hide();
    } else {
      QPoint buttonPos = ui->stickersButton->mapToGlobal(QPoint(0, 0));
      qDebug() << "Показ диалога стикеров в позиции:" << buttonPos;
      m_stickerPicker->showAtPosition(buttonPos);
    }
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при работе со стикерами:" << e.what();
  }
}

void MainWindow::onStickerSelected(const QString& stickerCode) {
  try {
    qDebug() << "Выбран стикер:" << stickerCode;

    QString curChatId = getcurChatId();

    if (curChatId.isEmpty()) {
      QMessageBox::warning(this, "Ошибка", "Выберите чат для отправки стикера");
      return;
    }

    if (!message_sender_) {
      qCritical() << "Message sender не инициализирован";
      QMessageBox::critical(this, "Ошибка", "Не удалось отправить стикер");
      return;
    }

    if (!chatContexts.contains(curChatId)) {
      qCritical() << "чат выбирался, но контекста такого нет";
      QMessageBox::critical(this, "Ошибка",
                            "чат выбирался, но контекста такого нет");
      return;
    }

    QByteArray stickerData = stickerCode.toUtf8();
    message_sender_->sendMessage(curChatId, stickerData, false);

    if (m_chatManager) {
      m_chatManager->loadChatHistory(curChatId);
    }

    qDebug() << "Стикер отправлен:" << stickerCode;
  } catch (const std::exception& e) {
    qCritical() << "Ошибка при отправке стикера:" << e.what();
    QMessageBox::critical(this, "Ошибка", "Не удалось отправить стикер");
  }
}

void MainWindow::syncChatsWithServer() {
  if (!SessionManager::instance().isLoggedIn()) {
    return;
  }

  grpc::ClientContext ctx;
  QString token = SessionManager::instance().sessionToken();
  if (!token.isEmpty()) {
    ctx.AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
  } else {
    QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
    return;
  }

  google::protobuf::Empty request;
  auto reader = chatStub_->GetActiveChats(&ctx, request);

  QSet<QString> serverChatIds;
  chat::ChatInfo chatInfo;

  while (reader->Read(&chatInfo)) {
    serverChatIds.insert(QString::fromStdString(chatInfo.chat_id()));
  }

  auto localChats =
      m_dbManager->getAllChats(SessionManager::instance().username());

  for (const auto& localChat : localChats) {
    if (!serverChatIds.contains(localChat.chatId)) {
      m_dbManager->removeChat(localChat.chatId,
                              SessionManager::instance().username());
      chatKeys.erase(localChat.chatId);
      chatContexts.erase(localChat.chatId);
    }
  }

  refreshChatsList();
}

void MainWindow::manualSyncChats() {
  if (m_isDestroying) {
    return;
  }
  if (!SessionManager::instance().isLoggedIn()) {
    QMessageBox::warning(this, "Ошибка", "Необходимо войти в систему");
    return;
  }

  qDebug() << "Ручная синхронизация чатов...";
  QtConcurrent::run(chatThreadPool, [this]() -> void {
    try {
      auto ctx = std::make_unique<grpc::ClientContext>();
      QString token = SessionManager::instance().sessionToken();
      if (!token.isEmpty()) {
        ctx->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
      } else {
        QMessageBox::critical(this, "Ошибка", "Необходимо войти в систему");
        return;
      }

      auto deadline =
          std::chrono::system_clock::now() + std::chrono::seconds(5);
      ctx->set_deadline(deadline);

      google::protobuf::Empty request;
      auto reader = chatStub_->GetActiveChats(ctx.get(), request);

      chat::ChatInfo chatInfo;
      while (reader->Read(&chatInfo)) {
        QString chatId = QString::fromStdString(chatInfo.chat_id());
        QString partiName = "";

        for (const auto& participant : chatInfo.participants()) {
          QString p = QString::fromStdString(participant);
          if (p != SessionManager::instance().username()) {
            partiName = p;
            break;
          }
        }

        QMetaObject::invokeMethod(
            this, [this, chatId, partiName, chatInfo]() -> void {
              onChatReceived(chatId, partiName, chatInfo.peer_params(),
                             chatInfo.encryption_params());
            });
      }

      reader->Finish();

      QMetaObject::invokeMethod(this, [this]() -> void {
        refreshChatsList();
        QMessageBox::information(this, "Успех", "Чаты обновлены");
      });

    } catch (const std::exception& e) {
      qCritical() << "Ошибка синхронизации:" << e.what();
      QMetaObject::invokeMethod(this, [this, e]() -> void {
        QMessageBox::critical(
            this, "Ошибка",
            QString("Не удалось обновить чаты: %1").arg(e.what()));
      });
    }
  });
}
