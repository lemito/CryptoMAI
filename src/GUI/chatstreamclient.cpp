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
  stop_requested_ = true;

  if (context_) {
    qDebug() << "Отмена контекста";
    context_->TryCancel();
  }

  if (stream_thread_.joinable()) {
    auto timeout = std::chrono::seconds(3);
    if (stream_thread_.joinable()) {
      stream_thread_.join();
      qDebug() << "Поток стопнут";
    } else {
      qWarning() << "Поток не получилось стопнуть";
    }
  }

  streaming_ = false;
  qDebug() << "Остановлено";
}

void ChatStreamClient::runStream() {
  try {
    context_ = std::make_unique<grpc::ClientContext>();

    auto deadline = std::chrono::system_clock::now() + std::chrono::hours(1);
    context_->set_deadline(deadline);

    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      context_->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    }

    google::protobuf::Empty request;
    std::unique_ptr<grpc::ClientReader<chat::ChatInfo>> reader(
        chatStub_->GetActiveChats(context_.get(), request));

    chat::ChatInfo chatInfo;
    emit streamStatusChanged(true);

    while (!stop_requested_) {
      bool has_message = reader->Read(&chatInfo);

      if (stop_requested_) {
        break;
      }

      if (!has_message) {
        break;
      }

      auto chatId = QString::fromStdString(chatInfo.chat_id());

      QMetaObject::invokeMethod(
          this, [this, chatId]() -> void { emit chatReceived(chatId); },
          Qt::QueuedConnection);

      qDebug() << "Received" << "ID:" << chatId;
    }

    grpc::Status status = reader->Finish();

    if (!stop_requested_) {
      if (!status.ok()) {
        QString error = QString::fromStdString(status.error_message());
        QMetaObject::invokeMethod(
            this,
            [this, error]() -> void {
              emit streamError(error);
              emit streamStatusChanged(false);
            },
            Qt::QueuedConnection);
        qDebug() << "ОШИБКА:" << error;
      } else {
        qDebug() << "СТОП";
        QMetaObject::invokeMethod(
            this, [this]() -> void { emit streamStatusChanged(false); },
            Qt::QueuedConnection);
      }
    } else {
      qDebug() << "ОСТАНОВЛЕНО";
    }

  } catch (const std::exception& e) {
    if (!stop_requested_) {
      QString error = QString("ОШИБКА: %1").arg(e.what());
      QMetaObject::invokeMethod(
          this,
          [this, error]() {
            emit streamError(error);
            emit streamStatusChanged(false);
          },
          Qt::QueuedConnection);
      qCritical() << "ОШИБКА:" << error;
    }
  }

  context_.reset();
  streaming_ = false;

  qDebug() << "Поток завершен";
}
