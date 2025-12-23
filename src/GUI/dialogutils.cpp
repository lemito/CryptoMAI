#include "dialogutils.h"
#include <QRegularExpression>
#include <QRandomGenerator>
#include <QTimer>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <QFutureWatcher>
#include <QtConcurrent>
#include <QMessageBox>
#include <QGroupBox>
#include <QLabel>

#include "cypher/DiffieHelman/rfc3526.hpp"

QByteArray bigIntToQByteArray(const BI& number) {
  std::ostringstream oss;
  oss << std::hex << number;
  std::string hexStr = oss.str();

  if (hexStr.length() % 2 != 0) {
    hexStr = "0" + hexStr;
  }

  return QByteArray::fromHex(QString::fromStdString(hexStr).toLatin1());
}

BI qByteArrayToBigInt(const QByteArray& data) {
  std::string hexStr = data.toHex().toStdString();
  BI number;
  std::istringstream iss(hexStr);
  iss >> std::hex >> number;
  return number;
}

QList<BI> generateDHParameters(int bitLength, double probability) {
  try {
    const auto [prime, generator] = get_dh_params(DH_STANDART_P_str_hex, DH_STANDART_G_str_hex);
    meow::cypher::DiffieHelman dh(prime, generator);

    const auto publicKey = dh.getPublicKey();
    const auto privateKey = dh.secret;

    return {prime, generator, publicKey, privateKey};
  } catch (const std::exception& e) {
    qCritical() << "Ошибка генерации DH параметров:" << e.what();
    return {};
  }
}

BaseChatDialog::BaseChatDialog(QWidget* parent)
    : QDialog(parent),
      dhWatcher(new QFutureWatcher<QList<BI>>(this)),
      progressBar(new QProgressBar(this)),
      buttonBox(nullptr)
{
  setupCommonStyles();
  connect(dhWatcher, &QFutureWatcher<QList<BI>>::finished,
          this, &BaseChatDialog::handleDHGenerationFinished);
}

BaseChatDialog::~BaseChatDialog() {
  if (dhWatcher->isRunning()) {
    dhWatcher->cancel();
    dhWatcher->waitForFinished();
  }
  safe_delete(dhWatcher);
}

void BaseChatDialog::setupCommonStyles() {
  setStyleSheet(R"(
              QDialog {
                  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                      stop:0 #1a1c1e, stop:1 #242526);
                  border-radius: 12px;
              }
              QLabel {
                  color: #e4e6eb;
                  font-size: 10pt;
              }
              QPushButton {
                  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                      stop:0 #a3c6ff, stop:1 #2a75f0);
                  color: white;
                  border: none;
                  border-radius: 6px;
                  padding: 8px 12px;
                  font-weight: 500;
                  font-size: 10pt;
                  min-width: 80px;
              }
              QPushButton:hover {
                  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                      stop:0 #2a75f0, stop:1 #205fcc);
              }
              QPushButton:pressed {
                  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                      stop:0 #205fcc, stop:1 #1a4d9c);
              }
              QProgressBar {
                  background-color: #2d3035;
                  border: 2px solid #3a3d44;
                  border-radius: 8px;
                  text-align: center;
                  color: #e4e6eb;
                  font-size: 9pt;
                  height: 20px;
              }
              QProgressBar::chunk {
                  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                      stop:0 #a3c6ff, stop:1 #2a75f0);
                  border-radius: 6px;
              }
              QGroupBox {
                  font-weight: bold;
                  color: #e4e6eb;
                  border: 2px solid #3a3d44;
                  border-radius: 10px;
                  margin-top: 10px;
                  padding-top: 15px;
                  background-color: rgba(45, 48, 53, 0.6);
              }
              QGroupBox::title {
                  subcontrol-origin: margin;
                  left: 15px;
                  padding: 0 10px;
                  color: #a3c6ff;
                  font-size: 11pt;
              }
              QLineEdit, QComboBox {
                  background-color: #2d3035;
                  border: 2px solid #3a3d44;
                  border-radius: 8px;
                  padding: 8px;
                  font-size: 10pt;
                  color: #e4e6eb;
              }
              QLineEdit:focus, QComboBox:focus {
                  border-color: #3a86ff;
                  background-color: #35383f;
              }
              QLineEdit::placeholder {
                  color: #8a8d91;
              }
              QComboBox QAbstractItemView {
                  background-color: #2d3035;
                  border: 1px solid #3a3d44;
                  color: #e4e6eb;
                  selection-background-color: #3a86ff;
              }
          )");
}

void BaseChatDialog::setupDHGeneration(int bitLength) {
  progressBar->setVisible(true);
  progressBar->setRange(0, 0);
  progressBar->setFormat("Генерация ключей Диффи-Хеллмана...");

  QFuture<QList<BI>> future = QtConcurrent::run(generateDHParameters, bitLength, 0.95);
  dhWatcher->setFuture(future);
}

void BaseChatDialog::handleDHGenerationFinished() {
  QList<BI> results = dhWatcher->result();

  if (results.size() >= 4) {
    dhPrime = results[0];
    dhGenerator = results[1];
    dhPublicKey = results[2];
    dhPrivateKey = results[3];

    qDebug() << "DH параметры успешно сгенерированы для диалога";
  } else {
    qCritical() << "Ошибка генерации DH параметров: недостаточно результатов";
    QMessageBox::critical(this, "Ошибка",
                          "Не удалось сгенерировать параметры Диффи-Хеллмана. Попробуйте еще раз.");
    clearDHParameters();
  }

  progressBar->setVisible(false);
  validateForm();
}

void BaseChatDialog::clearDHParameters() {
  dhPrime = 0;
  dhGenerator = 0;
  dhPublicKey = 0;
  dhPrivateKey = 0;
}
