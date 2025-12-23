#include "chatstreamclient.h"

#include <QDebug>

#include "sessionmanager.h"
#include "utils.hpp"

ChatStreamClient::ChatStreamClient(chat::ChatService::Stub* chatStub,
                                   QObject* parent)
    : QObject(parent), chatStub_(chatStub) {}

ChatStreamClient::~ChatStreamClient() { stopStream(); }

void ChatStreamClient::startStream() {
  if (streaming_) {
    return;
  }

  if (stream_thread_.joinable()) {
    stream_thread_.join();
  }

  streaming_ = true;
  stop_requested_ = false;
  session_token_ = SessionManager::instance().sessionToken();

  stream_thread_ = std::thread(&ChatStreamClient::runStream, this);
}

void ChatStreamClient::stopStream() {
  if (!streaming_) {
    qDebug() << "не стоп";
    return;
  }

  qDebug() << "стоп...";
  stop_requested_.store(true);

  if (context_) {
    qDebug() << "Отмена контекста";
    context_->TryCancel();
  }

  if (stream_thread_.joinable()) {
    auto start = std::chrono::steady_clock::now();
    while (streaming_.load() && 
           std::chrono::steady_clock::now() - start < std::chrono::seconds(1)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    if (streaming_.load()) {
      qWarning() << "Поток не завершился, используем detach";
      stream_thread_.detach();
    } else {
      stream_thread_.join();
      qDebug() << "Поток стопнут";
    }
  }

  streaming_.store(false);
  qDebug() << "Остановлено";
}


void ChatStreamClient::runStream() {
  try {
    if (!stop_requested_.load()) {
      auto context = std::make_unique<grpc::ClientContext>();
      QString token = SessionManager::instance().sessionToken();
      if (!token.isEmpty()) {
        context->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
      }

      google::protobuf::Empty request;
      auto reader = chatStub_->GetActiveChats(context.get(), request);

      chat::ChatInfo chatInfo;
      while (reader->Read(&chatInfo) && !stop_requested_.load()) {
        processChat(chatInfo);
      }
      reader->Finish();
    }

    while (!stop_requested_.load()) {
      try {
        context_ = std::make_unique<grpc::ClientContext>();
        QString token = SessionManager::instance().sessionToken();
        if (!token.isEmpty()) {
          context_->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
        }

        google::protobuf::Empty request;
        auto reader =
            chatStub_->SubscribeToChatUpdates(context_.get(), request);

        chat::ChatUpdate update;
        emit streamStatusChanged(true);

        while (reader->Read(&update) && !stop_requested_.load()) {
          if (update.has_chat()) {
            processChat(update.chat());
          }
        }

        auto status = reader->Finish();

        if (!stop_requested_.load()) {
          if (!status.ok()) {
            qDebug() << "Stream error:"
                     << QString::fromStdString(status.error_message());
          }
          qDebug() << "Переподключение через 3 секунды...";
          for (int i = 0; i < 30 && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          }
        }
      } catch (const std::exception& e) {
        if (!stop_requested_.load()) {
          qCritical() << "Ошибка в цикле обновлений:" << e.what();
          std::this_thread::sleep_for(std::chrono::seconds(3));
        }
      }
    }
  } catch (const std::exception& e) {
    if (!stop_requested_.load()) {
      qCritical() << "Ошибка:" << e.what();
    }
  }

  context_.reset();
  streaming_ = false;
  qDebug() << "Поток завершен";
}

void ChatStreamClient::processChat(const chat::ChatInfo& chatInfo) {
  QString currentUser = SessionManager::instance().username();

  bool isParticipant = false;
  for (int i = 0; i < chatInfo.participants_size(); ++i) {
    if (QString::fromStdString(chatInfo.participants(i)) == currentUser) {
      isParticipant = true;
      break;
    }
  }

  if (!isParticipant) {
    return;
  }

  QString partiName = QString::fromStdString(chatInfo.participants(0));
  if (partiName == currentUser && chatInfo.participants_size() == 2) {
    partiName = QString::fromStdString(chatInfo.participants(1));
  }

  QString chatId = QString::fromStdString(chatInfo.chat_id());

  QMetaObject::invokeMethod(
      this,
      [this, chatId, partiName, peerParams = chatInfo.peer_params(),
       algoParams = chatInfo.encryption_params()]() {
        emit chatReceived(chatId, partiName, peerParams, algoParams);
      },
      Qt::QueuedConnection);
}

// void ChatStreamClient::runStream() {
//   try {
//     context_ = std::make_unique<grpc::ClientContext>();

//     auto deadline = std::chrono::system_clock::now() + std::chrono::hours(1);
//     context_->set_deadline(deadline);

//     QString token = SessionManager::instance().sessionToken();
//     if (!token.isEmpty()) {
//       context_->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
//     }

//     google::protobuf::Empty request;
//     std::unique_ptr<grpc::ClientReader<chat::ChatInfo>> reader(
//         chatStub_->GetActiveChats(context_.get(), request));

//     chat::ChatInfo chatInfo;
//     emit streamStatusChanged(true);

//     while (!stop_requested_.load()) {
//       bool has_message = reader->Read(&chatInfo);

//       if (stop_requested_.load()) {
//         break;
//       }

//       // if (!has_message) {
//       //   break;
//       // }

//       QString currentUser = SessionManager::instance().username();

//       bool isParticipant = false;
//       for (int i = 0; i < chatInfo.participants_size(); ++i) {
//         if (QString::fromStdString(chatInfo.participants(i)) == currentUser)
//         {
//           isParticipant = true;
//           break;
//         }
//       }

//       if (isParticipant) {
//         QString partiName = QString::fromStdString(chatInfo.participants(0));
//         if (partiName == currentUser) {
//           if (chatInfo.participants().size() == 2)
//           {partiName = QString::fromStdString(chatInfo.participants(1));}
//           else {
//             qDebug() << "chatInfo.participants странный";
//           }
//         }
//         const QString chatId = QString::fromStdString(chatInfo.chat_id());
//         const ::chat::DHParameters& peerParams = chatInfo.peer_params();
//         const ::chat::EncryptionParameters& algoParams =
//             chatInfo.encryption_params();

//         QMetaObject::invokeMethod(
//             this,
//             [this, chatId, partiName, peerParams, algoParams]() -> void {
//               emit chatReceived(chatId, partiName, peerParams, algoParams);
//             },
//             Qt::QueuedConnection);

//         qDebug() << "Получен " << "ID:" << chatId << "для:" << currentUser;
//       } else {
//         qDebug() << "Чат "
//                  << "ID:" << QString::fromStdString(chatInfo.chat_id())
//                  << "пользователь не в чатике:" << currentUser;
//       }

//       if (!stop_requested_.load()) {
//         qDebug()
//             << "Переподключение потока обновлений чатов через 3 секунды...";
//         std::this_thread::sleep_for(std::chrono::seconds(3));
//       }
//     }

//     grpc::Status status = reader->Finish();

//     if (!stop_requested_.load()) {
//       if (!status.ok()) {
//         QString error = QString::fromStdString(status.error_message());
//         QMetaObject::invokeMethod(
//             this,
//             [this, error]() -> void {
//               emit streamError(error);
//               emit streamStatusChanged(false);
//             },
//             Qt::QueuedConnection);
//         qDebug() << "ОШИБКА:" << error;
//       } else {
//         qDebug() << "СТОП";
//         QMetaObject::invokeMethod(
//             this, [this]() -> void { emit streamStatusChanged(false); },
//             Qt::QueuedConnection);
//       }
//     } else {
//       qDebug() << "ОСТАНОВЛЕНО";
//     }

//   } catch (const std::exception& e) {
//     if (!stop_requested_.load()) {
//       QString error = QString("ОШИБКА: %1").arg(e.what());
//       QMetaObject::invokeMethod(
//           this,
//           [this, error]() -> void {
//             emit streamError(error);
//             emit streamStatusChanged(false);
//           },
//           Qt::QueuedConnection);
//       qCritical() << "ОШИБКА:" << error;
//     }
//   }

//   context_.reset();
//   streaming_ = false;

//   qDebug() << "Поток завершен";
// }
