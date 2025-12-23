#include "messageassembler.h"

#include <QDateTime>
#include <QDebug>

MessageAssembler::MessageAssembler(QObject* parent) : QObject(parent) {
  cleanupTimer_.setInterval(CLEANUP_INTERVAL);
  connect(&cleanupTimer_, &QTimer::timeout, this,
          &MessageAssembler::cleanupExpiredMessages);
  cleanupTimer_.start();
}

MessageAssembler::~MessageAssembler() {
  cleanupTimer_.stop();
  for (auto& assembly : assemblies_) {
    if (assembly.timeoutTimer != nullptr) {
      assembly.timeoutTimer->stop();
      safe_delete(assembly.timeoutTimer);
    }
  }
  assemblies_.clear();
}

void MessageAssembler::processChunk(const chat::EncryptedChunk& chunk) {
  const auto& metadata = chunk.metadata();
  QString messageId = QString::fromStdString(metadata.message_id());
  QString chatId = QString::fromStdString(metadata.chat_id());
  int chunkIndex = metadata.chunk_index();
  int totalChunks = metadata.total_chunks();
  bool isLastChunk = metadata.is_last_chunk();
  bool isFile = metadata.is_file();
  bool isCancellation = metadata.is_cancellation();

  qDebug() << "Обработка чанка:" << chunkIndex << "/" << totalChunks
           << "для сообщения:" << messageId << "последний?:" << isLastChunk;

  if (chunkIndex < 0 || totalChunks <= 0 || chunkIndex >= totalChunks) {
    emit assemblyError(messageId,
                       QString("Некорректные индексы чанков: %1/%2")
                           .arg(chunkIndex)
                           .arg(totalChunks));
    return;
  }

  if (!assemblies_.contains(messageId)) {
    MessageAssembly assembly;
    assembly.messageId = messageId;
    assembly.chatId = chatId;
    assembly.fileId = QString::fromStdString(metadata.file_id());
    assembly.originalFilename =
        QString::fromStdString(metadata.original_filename());
    assembly.fileSize = metadata.file_size();
    assembly.totalChunks = totalChunks;
    assembly.isFile = isFile;
    assembly.isCancellation = isCancellation;
    assembly.createdTime = QDateTime::currentDateTime();

    assembly.timeoutTimer = new QTimer(this);
    assembly.timeoutTimer->setSingleShot(true);
    assembly.timeoutTimer->setInterval(ASSEMBLY_INTERVAL);
    connect(assembly.timeoutTimer, &QTimer::timeout, [this, messageId]() {
      qWarning() << "Что-то очень долго :" << messageId;
      emit assemblyError(messageId, "Что-то очень долго ");
      cleanupMessage(messageId);
    });
    assembly.timeoutTimer->start();

    assemblies_[messageId] = assembly;

    qDebug() << "Начата сборка сообщения:" << messageId
             << "всего чанков:" << totalChunks << "файл:" << isFile;
  }

  MessageAssembly& assembly = assemblies_[messageId];

  if (assembly.totalChunks != totalChunks) {
    emit assemblyError(
        messageId,
        QString("Несовпадение количества чанков: ожидалось %1, получено %2")
            .arg(assembly.totalChunks)
            .arg(totalChunks));
    cleanupMessage(messageId);
    return;
  }

  if (assembly.chatId != chatId) {
    emit assemblyError(messageId, "Несовпадение ID чата во чанках");
    cleanupMessage(messageId);
    return;
  }

  if (assembly.receivedIndices.contains(chunkIndex)) {
    qDebug() << "Дубликат чанка" << chunkIndex << "для сообщения"
             << messageId;
    return;
  }

  QByteArray chunkData(chunk.encrypted_content().data(),
                       chunk.encrypted_content().size());
  assembly.chunks[chunkIndex] = chunkData;
  assembly.receivedIndices.insert(chunkIndex);
  assembly.receivedChunks++;

  qDebug() << "чанк" << chunkIndex << "получен для" << messageId
           << "прогресс:" << assembly.receivedChunks << "/"
           << assembly.totalChunks;

  checkAssemblyComplete(assembly);
}

void MessageAssembler::checkAssemblyComplete(MessageAssembly& assembly) {
  if (assembly.receivedChunks >= assembly.totalChunks) {
    bool allChunksReceived = true;
    for (int i = 0; i < assembly.totalChunks; ++i) {
      if (!assembly.receivedIndices.contains(i)) {
        allChunksReceived = false;
        qWarning() << "Отсутствует чанк" << i << "для сообщения"
                   << assembly.messageId;
        break;
      }
    }

    if (allChunksReceived) {
      qDebug() << "Все чанкы получены для сообщения:" << assembly.messageId;
      finalizeMessage(assembly);
    } else {
      assembly.receivedChunks = assembly.receivedIndices.size();
      qDebug() << "Не все чанкы получены для" << assembly.messageId << "("
               << assembly.receivedChunks << "/" << assembly.totalChunks << ")";
    }
  }
}

void MessageAssembler::finalizeMessage(MessageAssembly& assembly) {
  try {
    QByteArray assembledData;

    if (assembly.fileSize > 0) {
      assembledData.reserve(assembly.fileSize);
    } else {
      assembledData.reserve(
          static_cast<qsizetype>(assembly.totalChunks * CHUNK_SIZE));
    }

    for (int i = 0; i < assembly.totalChunks; ++i) {
      if (!assembly.chunks.contains(i)) {
        emit assemblyError(
            assembly.messageId,
            QString("Отсутствует чанк %1 при финальной сборке").arg(i));
        cleanupMessage(assembly.messageId);
        return;
      }
      assembledData.append(assembly.chunks[i]);
    }

    qDebug() << "Сообщение полностью собрано";

    chat::ChunkMetadata metadata;
    metadata.set_chat_id(assembly.chatId.toStdString());
    metadata.set_message_id(assembly.messageId.toStdString());
    metadata.set_file_id(assembly.fileId.toStdString());
    metadata.set_original_filename(assembly.originalFilename.toStdString());
    metadata.set_file_size(assembly.fileSize);
    metadata.set_is_file(assembly.isFile);
    metadata.set_is_cancellation(assembly.isCancellation);
    metadata.set_total_chunks(assembly.totalChunks);
    metadata.set_is_last_chunk(true);

    emit messageComplete(assembly.messageId, assembledData, metadata);
    cleanupMessage(assembly.messageId);

  } catch (const std::exception& e) {
    emit assemblyError(
        assembly.messageId,
        QString("Ошибка при сборке сообщения: %1").arg(e.what()));
    cleanupMessage(assembly.messageId);
  }
}

void MessageAssembler::cleanupMessage(const QString& messageId) {
  if (assemblies_.contains(messageId)) {
    MessageAssembly& assembly = assemblies_[messageId];
    if (assembly.timeoutTimer != nullptr) {
      assembly.timeoutTimer->stop();
      safe_delete(assembly.timeoutTimer);
    }
    assemblies_.remove(messageId);
    qDebug() << "Очистка сборки для сообщения:" << messageId;
  }
}

void MessageAssembler::cleanupExpiredMessages() {
  QDateTime now = QDateTime::currentDateTime();
  QList<QString> toRemove;

  for (auto it = assemblies_.begin(); it != assemblies_.end(); ++it) {
    if (it->createdTime.secsTo(now) > 300) {
      toRemove.append(it.key());
      qWarning() << "Сборка сообщения устарела:" << it->messageId;
      emit assemblyError(it->messageId, "Сборка сообщения устарела");
    }
  }

  for (const QString& messageId : toRemove) {
    cleanupMessage(messageId);
  }

  if (!toRemove.isEmpty()) {
    qDebug() << "Очищено" << toRemove.size() << "устаревших сборок сообщений";
  }
}
