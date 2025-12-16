#ifndef FILEUPLOADMANAGER_H
#define FILEUPLOADMANAGER_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVariantMap>
#include <memory>
#include <vector>

#include "miniocpp/client.h"
#include "miniocpp/credentials.h"

class FileUploadManager final : public QObject {
  Q_OBJECT

 public:
  static auto instance() -> FileUploadManager&;

  FileUploadManager(const FileUploadManager&) = delete;
  auto operator=(const FileUploadManager&) -> FileUploadManager& = delete;

  auto initialize(const QString& endpoint, const QString& accessKey,
                  const QString& secretKey, bool useSSL = false,
                  const QString& region = "us-east-1") -> bool;

  void uploadFile(const QString& bucketName, const QString& objectName,
                  const QString& filePath,
                  const QVariantMap& metadata = QVariantMap());

  void uploadFile(const QString& bucketName, const QString& objectName,
                  const QByteArray& data,
                  const QVariantMap& metadata = QVariantMap());

  void downloadFile(const QString& bucketName, const QString& objectName,
                    const QString& filePath);

  auto downloadFile(const QString& bucketName, const QString& objectName)
      -> QByteArray;

  auto deleteFile(const QString& bucketName, const QString& objectName) -> bool;

  auto createBucket(const QString& bucketName) -> bool;
  auto bucketExists(const QString& bucketName) -> bool;
  auto deleteBucket(const QString& bucketName) -> bool;
  auto listBuckets() -> std::vector<QString>;

  auto objectExists(const QString& bucketName, const QString& objectName)
      -> bool;
  auto listObjects(const QString& bucketName, const QString& prefix = "")
      -> std::vector<QString>;

  auto getObjectMetadata(const QString& bucketName, const QString& objectName)
      -> QVariantMap;

  auto generatePresignedUrl(const QString& bucketName,
                            const QString& objectName, int expirySeconds = 3600)
      -> QString;

  [[nodiscard]] auto isInitialized() const -> bool { return m_initialized; }
  [[nodiscard]] auto lastError() const -> QString { return m_lastError; }
  [[nodiscard]] auto endpoint() const -> QString { return m_endpoint; }

 signals:
  void uploadStarted(const QString& objectName, const QString& bucketName);
  void uploadProgress(const QString& objectName, qint64 bytesSent,
                      qint64 bytesTotal);
  void uploadFinished(const QString& objectName, const QString& fileUrl);
  void uploadFailed(const QString& objectName, const QString& error);

  void downloadStarted(const QString& objectName, const QString& bucketName);
  void downloadProgress(const QString& objectName, qint64 bytesReceived,
                        qint64 bytesTotal);
  void downloadFinished(const QString& objectName, const QString& localPath);
  void downloadFailed(const QString& objectName, const QString& error);

  void bucketCreated(const QString& bucketName);
  void bucketDeleted(const QString& bucketName);
  void bucketOperationFailed(const QString& bucketName, const QString& error);

  void objectDeleted(const QString& objectName, const QString& bucketName);
  void objectOperationFailed(const QString& objectName,
                             const QString& bucketName, const QString& error);

  void initialized(bool success, const QString& error = QString());
  void operationCompleted(const QString& operation, bool success,
                          const QString& message = QString());

 private:
  explicit FileUploadManager(QObject* parent = nullptr);
  ~FileUploadManager() override;

  template <typename Func, typename... Args>
  void executeAsync(const QString& operationName, Func&& func, Args&&... args);

  std::unique_ptr<minio::s3::Client> m_client;
  std::unique_ptr<minio::creds::StaticProvider> m_provider;
  QString m_endpoint;
  QString m_accessKey;
  QString m_secretKey;
  QString m_region;
  bool m_useSSL;
  bool m_initialized;
  QString m_lastError;
};

#endif  // FILEUPLOADMANAGER_H
