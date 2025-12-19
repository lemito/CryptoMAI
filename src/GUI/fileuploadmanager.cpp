#include "fileuploadmanager.h"

#include <QFile>
#include <QFileInfo>
#include <QThreadPool>
#include <QtConcurrent>
#include <fstream>
#include <sstream>

FileUploadManager::FileUploadManager(QObject* parent)
    : QObject(parent), m_useSSL(false), m_initialized(false) {}

FileUploadManager::~FileUploadManager() = default;

auto FileUploadManager::instance() -> FileUploadManager& {
  static FileUploadManager instance;
  return instance;
}

auto FileUploadManager::initialize(const QString& endpoint,
                                   const QString& accessKey,
                                   const QString& secretKey, bool useSSL,
                                   const QString& region) -> bool {
  try {
    qDebug() << "initialize start";
    m_endpoint = endpoint;
    m_accessKey = accessKey;
    m_secretKey = secretKey;
    m_useSSL = useSSL;
    m_region = region.isEmpty() ? "us-east-1" : region;

    minio::s3::BaseUrl baseUrl(endpoint.toStdString());
    baseUrl.https = useSSL;

    m_provider = std::make_unique<minio::creds::StaticProvider>(
        accessKey.toStdString(), secretKey.toStdString());

    m_client = std::make_unique<minio::s3::Client>(baseUrl, m_provider.get());

    minio::s3::BucketExistsArgs args;
    args.bucket = "test";

    minio::s3::BucketExistsResponse result = m_client->BucketExists(args);
    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      qDebug() << "" << m_lastError;
      emit initialized(false, m_lastError);
      return false;
    }

    m_initialized = true;
    m_lastError.clear();
    emit initialized(true);
    qDebug() << "initialize success";
    return true;

  } catch (const std::exception& e) {
    m_lastError = QString("Initialization failed: %1").arg(e.what());
    qDebug() << "" << m_lastError;
    emit initialized(false, m_lastError);
    return false;
  }
}

void FileUploadManager::uploadFile(const QString& bucketName,
                                   const QString& objectName,
                                   const QString& filePath,
                                   const QVariantMap& metadata) {
  qDebug() << "uploadFile вызван bucket:" << bucketName
           << "object:" << objectName << "file:" << filePath;
  if (!m_initialized) {
    qCritical() << "Manager not initialized";
    emit uploadFailed(objectName, "Manager not initialized");
    return;
  }

  execAsync("uploadFile", [this, bucketName, objectName, filePath,
                              metadata]() {
    qDebug() << "uploadStarted:" << objectName;
    emit uploadStarted(objectName, bucketName);

    try {
      QFile file(filePath);
      qDebug() << "Открытие файла:" << filePath;
      if (!file.open(QIODevice::ReadOnly)) {
        qCritical() << "Cannot open file:" << file.errorString();
        emit uploadFailed(
            objectName,
            QString("Cannot open file: %1").arg(file.errorString()));
        return;
      }

      qint64 fileSize = file.size();
      file.close();
      qDebug() << "Размер файла:" << fileSize;

      minio::utils::Multimap metaMap;
      for (auto it = metadata.constBegin(); it != metadata.constEnd(); ++it) {
        metaMap.Add(it.key().toStdString(),
                    it.value().toString().toStdString());
      }

      qDebug() << "Проверка bucket";
      minio::s3::BucketExistsArgs bucketArgs;
      bucketArgs.bucket = bucketName.toStdString();
      auto bucketResp = m_client->BucketExists(bucketArgs);
      if (!bucketResp || !bucketResp.exist) {
        qDebug() << "Создание bucket";
        minio::s3::MakeBucketArgs makeArgs;
        makeArgs.bucket = bucketName.toStdString();
        m_client->MakeBucket(makeArgs);
      }

      qDebug() << "Создание PutObjectArgs из файла";
      std::ifstream fileStream(filePath.toStdString(), std::ios::binary);
      if (!fileStream.is_open()) {
        emit uploadFailed(objectName, "Cannot open file stream");
        return;
      }

      minio::s3::PutObjectArgs args(fileStream, fileSize, 0);
      args.bucket = bucketName.toStdString();
      args.object = objectName.toStdString();
      args.user_metadata = metaMap;

      qDebug() << "Вызов PutObject bucket:" << bucketName
               << "object:" << objectName;
      minio::s3::PutObjectResponse result = m_client->PutObject(args);
      fileStream.close();
      if (!result) {
        qCritical() << "PutObject failed:"
                    << QString::fromStdString(result.Error().String());
        emit uploadFailed(objectName,
                          QString::fromStdString(result.Error().String()));
        return;
      }

      QString fileUrl = QString("%1://%2/%3/%4")
                            .arg(m_useSSL ? "https" : "http")
                            .arg(m_endpoint)
                            .arg(bucketName)
                            .arg(objectName);

      qDebug() << "файл загружен:" << fileUrl;

      emit uploadFinished(objectName, fileUrl);

    } catch (const std::exception& e) {
      qCritical() << "Exception:" << e.what();
      emit uploadFailed(objectName, QString("Upload failed: %1").arg(e.what()));
    }
  });
}

void FileUploadManager::uploadFile(const QString& bucketName,
                                   const QString& objectName,
                                   const QByteArray& data,
                                   const QVariantMap& metadata) {
  if (!m_initialized) {
    emit uploadFailed(objectName, "Manager not initialized");
    return;
  }

  execAsync("uploadFile", [this, bucketName, objectName, data, metadata]() {
    emit uploadStarted(objectName, bucketName);

    try {
      minio::utils::Multimap metaMap;
      for (auto it = metadata.constBegin(); it != metadata.constEnd(); ++it) {
        metaMap.Add(it.key().toStdString(),
                    it.value().toString().toStdString());
      }

      minio::s3::BucketExistsArgs bucketArgs;
      bucketArgs.bucket = bucketName.toStdString();
      auto bucketResp = m_client->BucketExists(bucketArgs);
      if (!bucketResp || !bucketResp.exist) {
        minio::s3::MakeBucketArgs makeArgs;
        makeArgs.bucket = bucketName.toStdString();
        m_client->MakeBucket(makeArgs);
      }

      std::istringstream iss(std::string(data.data(), data.size()));

      minio::s3::PutObjectArgs args(iss, data.size(), 0);
      args.bucket = bucketName.toStdString();
      args.object = objectName.toStdString();
      args.user_metadata = metaMap;

      minio::s3::PutObjectResponse result = m_client->PutObject(args);
      if (!result) {
        emit uploadFailed(objectName,
                          QString::fromStdString(result.Error().String()));
        return;
      }

      QString fileUrl = QString("%1://%2/%3/%4")
                            .arg(m_useSSL ? "https" : "http")
                            .arg(m_endpoint)
                            .arg(bucketName)
                            .arg(objectName);

      emit uploadFinished(objectName, fileUrl);

    } catch (const std::exception& e) {
      emit uploadFailed(objectName, QString("Upload failed: %1").arg(e.what()));
    }
  });
}

void FileUploadManager::downloadFile(const QString& bucketName,
                                     const QString& objectName,
                                     const QString& filePath) {
  if (!m_initialized) {
    emit downloadFailed(objectName, "Manager not initialized");
    return;
  }

  execAsync("downloadFile", [this, bucketName, objectName, filePath]() {
    emit downloadStarted(objectName, bucketName);

    try {
      minio::s3::GetObjectArgs args;
      args.bucket = bucketName.toStdString();
      args.object = objectName.toStdString();

      QFile file(filePath);
      if (!file.open(QIODevice::WriteOnly)) {
        emit downloadFailed(
            objectName,
            QString("Cannot create file: %1").arg(file.errorString()));
        return;
      }

      qint64 totalDownloaded = 0;
      qint64 totalSize = -1;

      args.datafunc = [&file, &totalDownloaded, this,
                       objectName](minio::http::DataFunctionArgs args) -> bool {
        if (args.datachunk.length() > 0) {
          qint64 written =
              file.write(args.datachunk.data(), args.datachunk.length());

          if (written != args.datachunk.length()) {
            return false;
          }

          totalDownloaded += written;
        }
        return true;
      };

      args.progressfunc = [&totalSize, &totalDownloaded, this, objectName](
                              minio::http::ProgressFunctionArgs args) -> bool {
        if (args.download_total_bytes > 0) {
          totalSize = args.download_total_bytes;
        }

        emit downloadProgress(objectName, totalDownloaded, totalSize);

        if (args.download_speed > 0) {
          return true;
        }

        return true;
      };

      minio::s3::GetObjectResponse resp = m_client->GetObject(args);

      file.close();

      if (resp) {
        emit downloadProgress(objectName, totalDownloaded, totalDownloaded);
        emit downloadFinished(objectName, filePath);
      } else {
        emit downloadFailed(objectName,
                            QString::fromStdString(resp.Error().String()));
      }

    } catch (const std::exception& e) {
      emit downloadFailed(objectName,
                          QString("Download failed: %1").arg(e.what()));
    }
  });
}

auto FileUploadManager::downloadFile(const QString& bucketName,
                                     const QString& objectName) -> QByteArray {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return {};
  }

  try {
    minio::s3::GetObjectArgs args;
    args.bucket = bucketName.toStdString();
    args.object = objectName.toStdString();

    QByteArray data;
    qint64 totalSize = -1;

    args.datafunc = [&data](minio::http::DataFunctionArgs args) -> bool {
      if (args.datachunk.length() > 0) {
        data.append(args.datachunk.data(), args.datachunk.length());
      }
      return true;
    };

    args.progressfunc =
        [&totalSize](minio::http::ProgressFunctionArgs args) -> bool {
      if (args.download_total_bytes > 0) {
        totalSize = args.download_total_bytes;
      }
      return true;
    };

    minio::s3::GetObjectResponse resp = m_client->GetObject(args);

    if (!resp) {
      m_lastError = QString::fromStdString(resp.Error().String());
      return QByteArray();
    }

    return data;

  } catch (const std::exception& e) {
    m_lastError = QString("Download failed: %1").arg(e.what());
    return {};
  }
}

auto FileUploadManager::deleteFile(const QString& bucketName,
                                   const QString& objectName) -> bool {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return false;
  }

  try {
    minio::s3::RemoveObjectArgs args;
    args.bucket = bucketName.toStdString();
    args.object = objectName.toStdString();

    minio::s3::RemoveObjectResponse result = m_client->RemoveObject(args);
    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      return false;
    }

    emit objectDeleted(objectName, bucketName);
    return true;

  } catch (const std::exception& e) {
    m_lastError = QString("Delete failed: %1").arg(e.what());
    return false;
  }
}

auto FileUploadManager::createBucket(const QString& bucketName) -> bool {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return false;
  }

  try {
    minio::s3::MakeBucketArgs args;
    args.bucket = bucketName.toStdString();

    auto result = m_client->MakeBucket(args);
    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      return false;
    }

    emit bucketCreated(bucketName);
    return true;

  } catch (const std::exception& e) {
    m_lastError = QString("Create bucket failed: %1").arg(e.what());
    return false;
  }
}

auto FileUploadManager::bucketExists(const QString& bucketName) -> bool {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return false;
  }

  try {
    minio::s3::BucketExistsArgs args;
    args.bucket = bucketName.toStdString();

    auto result = m_client->BucketExists(args);
    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      return false;
    }

    return result.exist;

  } catch (const std::exception& e) {
    m_lastError = QString("Bucket check failed: %1").arg(e.what());
    return false;
  }
}

auto FileUploadManager::listBuckets() -> std::vector<QString> {
  std::vector<QString> buckets;

  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return buckets;
  }

  try {
    auto result = m_client->ListBuckets();
    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      return buckets;
    }

    for (const auto& bucket : result.buckets) {
      buckets.push_back(QString::fromStdString(bucket.name));
    }

  } catch (const std::exception& e) {
    m_lastError = QString("List buckets failed: %1").arg(e.what());
  }

  return buckets;
}

auto FileUploadManager::objectExists(const QString& bucketName,
                                     const QString& objectName) -> bool {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return false;
  }

  try {
    minio::s3::StatObjectArgs args;
    args.bucket = bucketName.toStdString();
    args.object = objectName.toStdString();

    auto result = m_client->StatObject(args);
    return static_cast<bool>(result);

  } catch (const std::exception& e) {
    return false;
  }
}

auto FileUploadManager::listObjects(const QString& bucketName,
                                    const QString& prefix)
    -> std::vector<QString> {
  std::vector<QString> objects;

  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return objects;
  }

  try {
    std::string bucket = bucketName.toStdString();
    std::string prefixStr = prefix.toStdString();

    minio::s3::ListObjectsArgs args;
    args.bucket = bucket;
    if (!prefix.isEmpty()) {
      args.prefix = prefixStr;
    }

    auto result = m_client->ListObjects(args);
    if (!result) {
      return objects;
    }

    for (; result; result++) {
      const minio::s3::Item& item = *result;

      objects.push_back(QString::fromStdString(item.name));
    }

  } catch (const std::exception& e) {
    m_lastError = QString("List objects failed: %1").arg(e.what());
  }

  return objects;
}

auto FileUploadManager::generatePresignedUrl(const QString& bucketName,
                                             const QString& objectName,
                                             int expirySeconds) -> QString {
  if (!m_initialized) {
    m_lastError = "Manager not initialized";
    return {};
  }

  try {
    minio::s3::GetPresignedObjectUrlArgs args;
    args.bucket = bucketName.toStdString();
    args.object = objectName.toStdString();
    args.expiry_seconds = expirySeconds;

    auto result = m_client->GetPresignedObjectUrl(args);

    if (!result) {
      m_lastError = QString::fromStdString(result.Error().String());
      return {};
    }

    return QString::fromStdString(result.url);

  } catch (const std::exception& e) {
    m_lastError = QString("Generate URL failed: %1").arg(e.what());
    return {};
  }
}

template <typename Func, typename... Args>
void FileUploadManager::execAsync(const QString& operationName, Func&& func,
                                     Args&&... args) {
  auto res =
      QtConcurrent::run([this, operationName, func = std::forward<Func>(func),
                         args...]() mutable -> auto {
        try {
          qDebug() << "start fileuploadmanager|"<<operationName;
          func();
          qDebug() << "finished fileuploadmanager|"<<operationName;
        } catch (const std::exception& e) {
          qCritical() << "ошибка исполнения в fileuploadmanager|"<<operationName << ": "  << e.what();
          throw;
        }
      });
}
