#include "messagesender.h"

#include <grpcpp/grpcpp.h>

#include <QDebug>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QUuid>

#include "fileuploadmanager.h"
#include "sessionmanager.h"
#include "utils.hpp"

MessageSender::MessageSender(chat::MessagingService::Stub* messagingStub,
                             DatabaseManager* dbManager, QObject* parent)
    : QObject(parent),
      messagingStub_(messagingStub),
      dbManager_(dbManager),
      encryptCallback_(nullptr) {
  sender_thread_ = std::thread(&MessageSender::runSender, this);
}

MessageSender::~MessageSender() {
  stop_requested_ = true;
  // condition_.notify_all();
  condition_.SignalAll();
  if (sender_thread_.joinable()) {
    sender_thread_.join();
  }
}

void MessageSender::sendMessage(const QString& chatId, const QByteArray& data,
                                bool isFile) {
  QByteArray encryptedData = data;
  if (encryptCallback_) {
    if (!isFile) {
      encryptedData = encryptCallback_(chatId, data);
    } else {
      encryptedData = data;
    }
  } else {
    encryptedData = data;
  }

  auto chunks = prepareChunks(chatId, data, encryptedData, isFile);

  {
    absl::MutexLock lock(&queue_mutex_);
    chunks_queue_.push(std::move(chunks));
  }
  // condition_.notify_one();
  condition_.Signal();
}

void MessageSender::sendFileInfo(const QString& chatId, const QString& fileId,
                                 const QString& originalFileName,
                                 qint64 originalFileSize,
                                 const QString& mimeType, bool isFile,
                                 const QString& preview) {
  if (!isFile) {
    qCritical() << "isFile == false (подозрительное)";
  }
  qDebug() << "sendFileInfo вызван chatId:" << chatId << "fileId:" << fileId
           << "fileName:" << originalFileName;
  QString messageId = QUuid::createUuid().toString();
  QString username = SessionManager::instance().username();
  qDebug() << "messageId:" << messageId << "username:" << username;

  auto setMimeType = [](const QString& originalFileName) -> QString {
    if (originalFileName.endsWith(".jpg") ||
        originalFileName.endsWith(".jpeg") ||
        originalFileName.endsWith(".png") ||
        originalFileName.endsWith(".gif") ||
        originalFileName.endsWith(".webp")) {
      return "image";
    }
    if (originalFileName.endsWith(".mp4") ||
        originalFileName.endsWith(".webm")) {
      return "video";
    }
    if (originalFileName.endsWith(".mp3") ||
        originalFileName.endsWith(".wav") ||
        originalFileName.endsWith(".ogg")) {
      return "audio";
    }
    return "document";
  };

  if (dbManager_ != nullptr) {
    qDebug() << "Сохранение в БД";
    if (!dbManager_->addMessage(chatId, messageId, username, preview.toUtf8(),
                                false, true, MessageStatus::SENT, isFile,
                                fileId, setMimeType(originalFileName),
                                originalFileSize, username, originalFileName)) {
      qCritical() << "не удалось сохранить информацию о файле в БД";
      return;
    }
    qDebug() << "Сохранено в БД";
  }

  qDebug() << "Создание метаданных";
  chat::EncryptedChunk metadataChunk;
  auto metadata = createMetadata(chatId, messageId, fileId, originalFileName,
                                 originalFileSize, mimeType, isFile, 1, 0);
  metadataChunk.mutable_metadata()->CopyFrom(metadata);
  metadataChunk.set_encrypted_content("");

  std::vector<chat::EncryptedChunk> chunks_to_send;
  chunks_to_send.push_back(metadataChunk);

  qDebug() << "Добавление в очередь";
  {
    absl::MutexLock lock(&queue_mutex_);
    chunks_queue_.push(std::move(chunks_to_send));
  }
  condition_.Signal();
  qDebug() << "Метаданные файла отправлены:" << originalFileName;
}

void MessageSender::sendFile(const QString& chatId, const QString& filePath) {
  QFile file(filePath);
  if (!file.open(QIODevice::ReadOnly)) {
    qCritical() << "Не удалось открыть файл:" << filePath;
    return;
  }

  QByteArray fileData = file.readAll();
  file.close();

  qDebug() << fileData.size();

  sendMessage(chatId, fileData, true);
}

void MessageSender::runSender() {
  while (!stop_requested_) {
    std::vector<chat::EncryptedChunk> chunks;

    {
      absl::MutexLock lock(&queue_mutex_);
      // condition_.wait(lock, [this]() -> bool {
      //   return stop_requested_ || !chunks_queue_.empty();
      // });
      while (!stop_requested_ && chunks_queue_.empty()) {
        condition_.Wait(&queue_mutex_);
      }

      if (stop_requested_) {
        break;
      }

      chunks = std::move(chunks_queue_.front());
      chunks_queue_.pop();
    }

    auto context = std::make_unique<grpc::ClientContext>();
    QString token = SessionManager::instance().sessionToken();
    if (!token.isEmpty()) {
      context->AddMetadata(SESSION_TOKEN_HEADER, token.toStdString());
    }

    std::unique_ptr<grpc::ClientReaderWriter<chat::EncryptedChunk,
                                             chat::ChunkAcknowledgement>>
        stream(messagingStub_->SendChunks(context.get()));

    bool write_success = true;
    for (const auto& chunk : chunks) {
      if (stop_requested_) {
        break;
      }

      if (!stream->Write(chunk)) {
        qWarning() << "Поток SendChunks прерван во время записи";
        write_success = false;
        break;
      }

      qDebug() << "Отправлен фрагмент:" << chunk.metadata().chunk_index() << "/"
               << chunk.metadata().total_chunks() << "для сообщения:"
               << QString::fromStdString(chunk.metadata().message_id());
    }

    if (write_success) {
      stream->WritesDone();

      chat::ChunkAcknowledgement ack;
      while (stream->Read(&ack)) {
        qDebug() << "Получено подтверждение для фрагмента:" << ack.chunk_index()
                 << "файл:" << QString::fromStdString(ack.file_id())
                 << "успешно:" << ack.success();

        if (!ack.success()) {
          qWarning() << "Доставка фрагмента не удалась:"
                     << QString::fromStdString(ack.error());
        }
      }
    }

    grpc::Status status = stream->Finish();

    if (!status.ok()) {
      qCritical() << "Отправка фрагментов не удалась:"
                  << QString::fromStdString(status.error_message());
    } else {
      qDebug() << "Отправка фрагментов успешно завершена";
    }
  }
}

auto MessageSender::prepareChunks(const QString& chatId,
                                  const QByteArray& originalData,
                                  const QByteArray& encryptedData, bool isFile)
    -> std::vector<chat::EncryptedChunk> {
  std::vector<chat::EncryptedChunk> chunks;

  QString messageId = QUuid::createUuid().toString();

  if (dbManager_ != nullptr) {
    QString filename = "";
    QString content = "";
    if (isFile) {
      filename = "file_" + messageId;
    } else {
      content = QString::fromUtf8(originalData);
    }

    auto nick = SessionManager::instance().username();

    if (!dbManager_->addMessage(chatId, messageId, nick, content.toUtf8(),
                                false, true, MessageStatus::SENT, isFile,
                                filename, "mime", originalData.size(), nick)) {
      qCritical() << "не удалось сохранить соо в БД, оно не отправилось";
      return {};
    }
  }

  int totalChunks = (encryptedData.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;

  for (int i = 0; i < totalChunks; ++i) {
    chat::EncryptedChunk chunk;

    auto metadata = createMetadata(chatId, messageId, "", "", 0, "", isFile,
                                   totalChunks, i);
    chunk.mutable_metadata()->CopyFrom(metadata);

    size_t start = i * CHUNK_SIZE;
    size_t end = (start + CHUNK_SIZE < encryptedData.size())
                     ? start + CHUNK_SIZE
                     : encryptedData.size();
    size_t chunkSize = end - start;

    QByteArray chunkData = encryptedData.mid(start, chunkSize);
    chunk.set_encrypted_content(chunkData.data(), chunkSize);

    chunks.push_back(chunk);
  }

  qDebug() << "Подготовлено фрагментов:" << chunks.size()
           << "для сообщения:" << messageId;

  return chunks;
}

auto MessageSender::createMetadata(
    const QString& chatId, const QString& messageId, const QString& fileId,
    const QString& originalFilename, qint64 originalFileSize,
    const QString& mimeType, bool isFile, int totalChunks, int chunkIndex)
    -> chat::ChunkMetadata {
  chat::ChunkMetadata metadata;

  metadata.set_chat_id(chatId.toStdString());
  metadata.set_message_id(messageId.toStdString());
  metadata.set_is_file(isFile);
  metadata.set_chunk_index(chunkIndex);
  metadata.set_total_chunks(totalChunks);
  metadata.set_is_last_chunk(chunkIndex == totalChunks - 1);

  if (isFile) {
    metadata.set_file_id(fileId.toStdString());
    metadata.set_original_filename(originalFilename.toStdString());
    metadata.set_file_size(originalFileSize);
  }

  return metadata;
}
