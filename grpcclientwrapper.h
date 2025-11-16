#ifndef GRPCCLIENTWRAPPER_H
#define GRPCCLIENTWRAPPER_H

#include <QObject>
#include <QThread>
#include <memory>

class GrpcClientWrapper : public QObject {
  Q_OBJECT
 public:
  explicit GrpcClientWrapper(QObject* parent = nullptr);

 signals:

 private:
  std::unique_ptr<grpc::Channel> channel_;
  std::unique_ptr<authService::Stub> stub_;
  QThread* workerThread_;
};

#endif  // GRPCCLIENTWRAPPER_H
