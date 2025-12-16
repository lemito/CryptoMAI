#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <grpcpp/grpcpp.h>

#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFuture>
#include <QGroupBox>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMainWindow>
#include <QStringListModel>
#include <QThread>
#include <QtConcurrent>
#include <QtQuickWidgets>
#include <memory>
#include <mutex>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "chatmanager.h"
#include "chatstreamclient.h"
#include "choicedialog.h"
#include "contactsdialog.h"
#include "createchatdialog.h"
#include "cypher/DiffieHelman/rfc3526.hpp"
#include "cypher/SymmetricAlgorithms/LOKI97/loki97.hpp"
#include "cypher/SymmetricAlgorithms/RC6/rc6.hpp"
#include "databasemanager.h"
#include "fileuploadmanager.h"
#include "joinchatdialog.h"
#include "logindialog.h"
#include "math/math.hpp"
#include "messageassembler.h"
#include "messagesender.h"
#include "messagestreamclient.h"
#include "proto/chat.grpc.pb.h"
#include "proto/chat.pb.h"
#include "src/GUI/ui_mainwindow.h"
#include "utils.hpp"
#include "utils_math.h"

struct ChatKeys {
  BI symmetricKey;  // Общий секретный ключ
  BI myPrivateKey;
  BI myPublicKey;
  BI peerPublicKey;
  BI prime;
  BI generator;
  bool isInitialized = false;
  // meow::cypher::DiffieHelman dh;
};

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow();
  // void exchangeDHParameters(const QString& chatId, const BI& prime,
  //                           const BI& generator);
  void exchangeDHParameters(const QString& chatId);

 signals:
  void logoutRequested();

 public slots:
  void onLoginSuccess(const QString& username, const QString& token);
  void onLogout();

 protected:
  void closeEvent(QCloseEvent* event) override;
  auto eventFilter(QObject* obj, QEvent* event) -> bool override;

 private:
  Ui::MainWindow* ui{nullptr};
  QLabel* m_userLabel{nullptr};
  QPushButton* m_logoutButton{nullptr};
  ChoiceDialog* choiceDialog{nullptr};
  CreateChatDialog* createChatDialog{nullptr};
  JoinChatDialog* joinChatDialog{nullptr};
  QQuickWidget* chat{nullptr};
  QStringListModel* messagesModel{nullptr};

  SessionManager* m_sessionManager{nullptr};
  DatabaseManager* m_dbManager{nullptr};
  FileUploadManager& m_fileManager;

  std::unique_ptr<chat::AuthService::Stub> authStub_;
  std::unique_ptr<chat::ChatService::Stub> chatStub_;
  std::unique_ptr<chat::MessagingService::Stub> messagingStub_;

  std::unique_ptr<ChatStreamClient> chat_stream_client_;
  std::unique_ptr<MessageStreamClient> message_stream_client_;
  std::unique_ptr<MessageSender> message_sender_;

  std::unique_ptr<ContactsDialog> contactsDialog;
  std::unique_ptr<ChatManager> m_chatManager;

  absl::flat_hash_map<QString, ChatKeys> chatKeys;

  absl::Mutex chatContextMutex_;
  absl::flat_hash_map<QString, meow::cypher::symm::SymmetricCypherContext>
      chatContexts;

  absl::flat_hash_map<
      std::string,
      std::pair<std::shared_ptr<grpc::ClientContext>,
                std::shared_ptr<grpc::ClientReaderWriter<
                    chat::DHParametersExchange, chat::DHParametersResponse>>>>
      activeDHStreams_;
  absl::flat_hash_map<std::string, bool> activeDHExchanges_;

  absl::Mutex activeDHMutex_;

  absl::Mutex chatKeysMutex;
  QThreadPool* chatThreadPool;
  std::atomic<bool> m_isDestroying{false};

  void refreshChatsList();
  void initializeExistingChats();
  void setupUserInterface();
  void updateUserInfo();
  void startChatStream();
  void stopChatStream();
  void startMessageStream();
  void stopMessageStream();
  void onMessageSaved(const QString& messageId, const QString& chatId);
  void onChatSettingsButton_clicked();
  void initializeExistingChat(const QString& chatId);

  auto createContext(const Chat& chatInfo, const BI& symmetricKey)
      -> meow::cypher::symm::SymmetricCypherContext;
  auto encryptMessage(const QString& chatId, const QByteArray& plaintext)
      -> QByteArray;
  auto decryptMessage(const QString& chatId, const QByteArray& ciphertext)
      -> QByteArray;
  auto checkAndInitChatKeys(const QString& chatId) -> bool;

  // auto ensureMyDHParameters(const QString& chatId) -> QList<BI>;
  void startDHExchange(const QString& chatId);
  void computeSharedSecretAndInitializeContext(const QString& chatId);

  void updateDownloadStatus(const QString& message);
  QString formatBytes(qint64 bytes);

  QLabel* m_statusLabel;
  QProgressBar* m_progressBar;
  QPlainTextEdit* m_logWidget;
  QString m_currentDownload;

 private slots:
  void onWindowDestroyed() { emit destroyed(); }
  void showContactsDialog();
  void onUserStatusButton_clicked();
  void onContactsButton_clicked();
  void onChatReceived(const QString& chatId, const QString& partiName,
                      const ::chat::DHParameters& peerParams,
                      const ::chat::EncryptionParameters& algoParams);
  void onStreamError(const QString& error);

  void onMessageReceived(const chat::EncryptedChunk& chunk);
  void onMessageStreamError(const QString& error);

  void onSendMessageClicked();
  void onSendFileClicked();
  [[nodiscard]] auto getCurrentChatId() const -> QString;

  void onNewChatClicked();
  void onCreateChatRequested();
  void onJoinChatRequested();
  void handleCreateChat(const QString& contact, int algorithm, int mode,
                        int padding, const QByteArray& iv, const BI& prime,
                        const BI& generator, const BI& publicKey,
                        const BI& privateKey);
  void handleJoinChat(const QString& chatId, const BI& prime,
                      const BI& generator, const BI& publicKey,
                      const BI& privateKey);

  void processChatInBackground(const QString& chatId, const QString& partiName,
                               const ::chat::DHParameters& peerParams,
                               const ::chat::EncryptionParameters& algoParams);

  void onDownloadProgress(const QString& objectName, qint64 bytesReceived,
                          qint64 bytesTotal);
  void onDownloadFinished(const QString& objectName, const QString& filePath);
  void onDownloadFailed(const QString& objectName, const QString& errorMessage);
  void downloadFile(const QString& fileId);
};
#endif  // MAINWINDOW_H
