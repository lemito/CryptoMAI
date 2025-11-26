#ifndef DIALOGUTILS_H
#define DIALOGUTILS_H

#include <QByteArray>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFutureWatcher>
#include <QProgressBar>

#include "cypher/DiffieHelman/DiffieHelman.hpp"
#include "utils_math.h"

auto bigIntToQByteArray(const BI& number) -> QByteArray;
auto qByteArrayToBigInt(const QByteArray& data) -> BI;
auto generateDHParameters(int bitLength, double probability)
    -> QList<QByteArray>;

class BaseChatDialog : public QDialog {
  Q_OBJECT

 protected:
  QFutureWatcher<QList<QByteArray>>* dhWatcher;
  QProgressBar* progressBar;
  QDialogButtonBox* buttonBox;

  QByteArray dhPrime;
  QByteArray dhGenerator;
  QByteArray dhPublicKey;

  explicit BaseChatDialog(QWidget* parent = nullptr);
  ~BaseChatDialog() override;

  void setupCommonStyles();
  void setupDHGeneration(int bitLength = 1024);
  virtual void handleDHGenerationFinished();
  void clearDHParameters();
  virtual void validateForm() = 0;

 public:
  [[nodiscard]] auto getPrime() const -> QByteArray { return dhPrime; }
  [[nodiscard]] auto getGenerator() const -> QByteArray { return dhGenerator; }
  [[nodiscard]] auto getPublicKey() const -> QByteArray { return dhPublicKey; }
};

#endif  // DIALOGUTILS_H
