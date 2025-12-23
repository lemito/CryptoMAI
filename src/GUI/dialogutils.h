#ifndef DIALOGUTILS_H
#define DIALOGUTILS_H

#include <QByteArray>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFutureWatcher>
#include <QProgressBar>

#include "cypher/DiffieHelman/DiffieHelman.hpp"
#include "utils.hpp"
#include "utils_math.h"

auto bigIntToQByteArray(const BI& number) -> QByteArray;
auto qByteArrayToBigInt(const QByteArray& data) -> BI;
auto generateDHParameters(int bitLength, double probability) -> QList<BI>;

class BaseChatDialog : public QDialog {
  Q_OBJECT

 public:
  explicit BaseChatDialog(QWidget* parent = nullptr);
  ~BaseChatDialog();

  // DH параметры
  BI dhPrime;
  BI dhGenerator;
  BI dhPublicKey;
  BI dhPrivateKey;
  void clearDHParameters();

 public slots:
  virtual void validateForm() = 0;
  virtual void handleDHGenerationFinished();

 protected:
  void setupCommonStyles();
  void setupDHGeneration(int bitLength);

  QFutureWatcher<QList<BI>>* dhWatcher;
  QProgressBar* progressBar;
  QDialogButtonBox* buttonBox;
};

#endif  // DIALOGUTILS_H
