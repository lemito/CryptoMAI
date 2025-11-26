#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <grpcpp/grpcpp.h>

#include <QMainWindow>
#include <QMap>
#include <memory>

#include "chatstreamclient.h"
#include "choicedialog.h"
#include "contactsdialog.h"
#include "createchatdialog.h"
#include "databasemanager.h"
#include "joinchatdialog.h"
#include "logindialog.h"
#include "proto/chat.grpc.pb.h"
#include "proto/chat.pb.h"

struct ChatKeys {
  QByteArray sharedSecret;
  QByteArray symmetricKey;
  bool isInitialized = false;
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

 signals:
  void logoutRequested();

 public slots:
  void onLoginSuccess(const QString& username, const QString& token);
  void onLogout();

 protected:
  void closeEvent(QCloseEvent* event) override;

 private:
  Ui::MainWindow* ui;
  QLabel* m_userLabel;
  QPushButton* m_logoutButton;
  ChoiceDialog* choiceDialog;
  CreateChatDialog* createChatDialog;
  JoinChatDialog* joinChatDialog;

  SessionManager* m_sessionManager;
  DatabaseManager* m_dbManager;

  std::unique_ptr<chat::AuthService::Stub> authStub_;
  std::unique_ptr<chat::ChatService::Stub> chatStub_;
  std::unique_ptr<ChatStreamClient> chat_stream_client_;
  std::unique_ptr<ContactsDialog> contactsDialog;

  QMap<QString, ChatKeys> chatKeys;

  void setupUserInterface();
  void updateUserInfo();
  void startChatStream();
  void stopChatStream();

 private slots:
  void onWindowDestroyed() { emit destroyed(); }
  void showContactsDialog();
  void onUserStatusButton_clicked();
  void onContactsButton_clicked();
  void onChatReceived(const QString& chatId);
  void onStreamError(const QString& error);
  // void onStreamStatusChanged(bool connected);

  void onNewChatClicked();
  void onCreateChatRequested();
  void onJoinChatRequested();
  void handleCreateChat(const QString& contact, int algorithm, int mode,
                        int padding, const QByteArray& iv,
                        const QByteArray& prime, const QByteArray& generator,
                        const QByteArray& publicKey);
  void handleJoinChat(const QString& chatId, const QByteArray& prime,
                      const QByteArray& generator, const QByteArray& publicKey);
};
#endif  // MAINWINDOW_H
