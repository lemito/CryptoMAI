#include "messagestreamclient.h"

#include <grpcpp/grpcpp.h>

#include <QDebug>

#include "sessionmanager.h"
#include "utils.hpp"

MessageStreamClient::MessageStreamClient(
    chat::MessagingService::Stub* messagingStub, DatabaseManager* dbManager,
    QObject* parent)
    : QObject(parent),
      messagingStub_(messagingStub),
      dbManager_(dbManager),
      decryptCallback_(nullptr),
      messageAssembler_(std::make_unique<MessageAssembler>()) {
  connect(messageAssembler_.get(), &MessageAssembler::messageComplete, this,
          &MessageStreamClient::saveMessageToDatabase, Qt::QueuedConnection);
}

MessageStreamClient::~MessageStreamClient() { stopStream(); }

void MessageStreamClient::startStream() {
  if (streaming_) {
    qDebug() << "MessageStream: Уже запущен";
    return;
  }

  qDebug() << "MessageStreamClient::startStream";

    if (stream_thread_.joinable()) {
    stream_thread_.join();
  }

  streaming_ = true;
  stop_requested_ = false;

  stream_thread_ = std::thread(&MessageStreamClient::runStream, this);
}

void MessageStreamClient::stopStream() {
  if (!streaming_) {
    return;
  }

  stop_requested_ = true;

  if (context_) {
    context_->TryCancel();
  }

  if (stream_thread_.joinable()) {
    stream_thread_.join();
  }

  streaming_ = false;
  qDebug() << "MessageStream: Остановлен";
}

void MessageStreamClient::runStream() {
  try {
    context_ = std::make_unique<grpc::ClientContext>();

    auto deadline = std::chrono::system_clock::now() + std::chrono::hours(1);
    context_->set_deadline(deadline);

    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      context_->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
      qDebug() << "MessageStream: Токен добавлен в заголовки";
    } else {
      qWarning() << "MessageStream: Токен сессии пустой!";
    }

    chat::SubscribeToChunksRequest request;
    // request.set_chat_id("");

    qDebug() << "MessageStream: все чаты пользователя";

    std::unique_ptr<grpc::ClientReader<chat::EncryptedChunk>> reader(
        messagingStub_->SubscribeToChunks(context_.get(), request));

    if (!reader) {
      qCritical()
          << "MessageStream: Не удалось создать reader для SubscribeToChunks";
      emit streamError("Не удалось создать поток для получения сообщений");
      emit streamStatusChanged(false);
      context_.reset();
      streaming_ = false;
      return;
    }

    chat::EncryptedChunk chunk;
    emit streamStatusChanged(true);
    qDebug() << "MessageStream: Поток создан, начинаем чтение...";

    int chunkCount = 0;
    qDebug() << "MessageStream: Входим в цикл чтения, ожидаем сообщения от "
                "сервера...";

    while (!stop_requested_) {
      bool has_message = reader->Read(&chunk);
      qDebug() << "MessageStream: read";

      if (stop_requested_) {
        qDebug() << "MessageStream: Остановка запрошена во время чтения";
        break;
      }

      if (!has_message) {
        qDebug() << "MessageStream:  поток завершен или ошибка";
        break;
      }

      chunkCount++;
      qDebug() << "MessageStream: Получен чанк #" << chunkCount
               << "для сообщения:"
               << QString::fromStdString(chunk.metadata().message_id())
               << "чат:" << QString::fromStdString(chunk.metadata().chat_id())
               << "чанк:" << chunk.metadata().chunk_index() + 1 << "/"
               << chunk.metadata().total_chunks();

      processReceivedChunk(chunk);

      QMetaObject::invokeMethod(
          this, [this, chunk]() -> void { emit messageReceived(chunk); },
          Qt::QueuedConnection);
    }

    qDebug() << "MessageStream: Всего получено чанков:" << chunkCount;

    grpc::Status status = reader->Finish();

    if (!stop_requested_) {
      if (!status.ok()) {
        QString error = QString::fromStdString(status.error_message());
        QString details = QString("Код: %1, Сообщение: %2")
                              .arg(status.error_code())
                              .arg(error);
        QMetaObject::invokeMethod(
            this,
            [this, details]() -> void {
              emit streamError(details);
              emit streamStatusChanged(false);
            },
            Qt::QueuedConnection);
        qWarning() << "MessageStream: ОШИБКА завершения потока:" << details;
      } else {
        qDebug()
            << "MessageStream: Поток завершен нормально (status.ok() == true)";
        QMetaObject::invokeMethod(
            this, [this]() -> void { emit streamStatusChanged(false); },
            Qt::QueuedConnection);
      }
    } else {
      qDebug() << "MessageStream: Остановлен по запросу пользователя";
    }

  } catch (const std::exception& e) {
    if (!stop_requested_) {
      QString error = QString("MessageStream: Исключение: %1").arg(e.what());
      QMetaObject::invokeMethod(
          this,
          [this, error]() {
            emit streamError(error);
            emit streamStatusChanged(false);
          },
          Qt::QueuedConnection);
      qCritical() << error;
    }
  }

  context_.reset();
  streaming_ = false;

  qDebug() << "MessageStream: Поток завершен";
}

void MessageStreamClient::processReceivedChunk(
    const chat::EncryptedChunk& chunk) {
  messageAssembler_->processChunk(chunk);

  qDebug() << "MessageStream: Обрабатываем чанк для сообщения:"
           << QString::fromStdString(chunk.metadata().message_id())
           << "чат:" << QString::fromStdString(chunk.metadata().chat_id())
           << "чанк:" << chunk.metadata().chunk_index() + 1 << "/"
           << chunk.metadata().total_chunks();
}

void MessageStreamClient::saveMessageToDatabase(
    const QString& messageId, const QByteArray& assembledData,
    const chat::ChunkMetadata& metadata) {
  qDebug() << "сохранено в БД: " << messageId;

  if (dbManager_ == nullptr) {
    qWarning() << "MessageStream: DB не доступно";
    return;
  }

  QString chatId = QString::fromStdString(metadata.chat_id());
  bool isFile = metadata.is_file();

  qDebug() << "Chat ID" << chatId;
  qDebug() << "Is File" << (isFile ? "YES" : "NO");
  qDebug() << "Data Size:" << assembledData.size() << " bytes";

  Chat chat =
      dbManager_->getChat(chatId, SessionManager::instance().username());
  QString sender = chat.name.split("|")[0];
  // QString sender = SessionManager::instance().username();

  QByteArray decryptedData;
  QString fileId;

  if (isFile) {
    fileId = QString::fromStdString(metadata.file_id());
    decryptedData = QByteArray();
  } else if (decryptCallback_) {
    decryptedData = decryptCallback_(chatId, assembledData);
  } else {
    decryptedData = assembledData;
  }

  try {
    if (isFile) {
      QString originalFilename =
          QString::fromStdString(metadata.original_filename());

      bool success = dbManager_->addMessage(
          chatId, messageId, sender, decryptedData, false, false,
          MessageStatus::DELIVERED, true, fileId, "mime", metadata.file_size(),
          SessionManager::instance().username(), originalFilename);

      if (success) {
        qDebug() << "MessageStream: Файл сохранен в БД:" << messageId
                 << "fileId:" << fileId;
        QMetaObject::invokeMethod(
            this,
            [this, messageId, chatId]() -> void {
              emit messageSaved(messageId, chatId);
            },
            Qt::QueuedConnection);
      } else {
        qCritical() << "MessageStream: Ошибка сохранения файла в БД:"
                    << messageId;
      }

    } else {
      QString messageText = QString::fromUtf8(decryptedData);
      bool success = dbManager_->addMessage(
          chatId, messageId, sender, decryptedData, false, false,
          MessageStatus::DELIVERED, false, "", "", 0,
          SessionManager::instance().username());

      if (success) {
        qDebug() << "MessageStream: Текст сохранен в БД:" << messageId;
        qDebug() << "  Content: " << messageText.left(100);
        QMetaObject::invokeMethod(
            this,
            [this, messageId, chatId]() -> void {
              emit messageSaved(messageId, chatId);
            },
            Qt::QueuedConnection);
      } else {
        qCritical() << "MessageStream: Ошибка сохранения текста в БД:"
                    << messageId;
      }
    }

  } catch (const std::exception& e) {
    qCritical() << "MessageStream: Исключение при сохранении в БД:" << e.what();
  }
}
