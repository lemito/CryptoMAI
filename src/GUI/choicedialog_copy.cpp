#include "choicedialog.h"
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

QList<QByteArray> generateDHParameters(int bitLength, double probability) {
  try {
    meow::cypher::DiffieHelmanParams params(bitLength, probability);
    meow::cypher::DiffieHelman dh(params);

    QByteArray prime = bigIntToQByteArray(params.getModulus());
    QByteArray generator = bigIntToQByteArray(params.getGenerator());
    QByteArray publicKey = bigIntToQByteArray(dh.getPublicKey());

    return {prime, generator, publicKey};
  } catch (const std::exception& e) {
    qCritical() << "Ошибка генерации DH параметров:" << e.what();
    return {};
  }
}

class BaseChatDialog : public QDialog {
  Q_OBJECT
 protected:
  QFutureWatcher<QList<QByteArray>>* dhWatcher;
  QProgressBar* progressBar;
  QDialogButtonBox* buttonBox;

  QByteArray dhPrime;
  QByteArray dhGenerator;
  QByteArray dhPublicKey;

  explicit BaseChatDialog(QWidget* parent = nullptr)
      : QDialog(parent),
        dhWatcher(new QFutureWatcher<QList<QByteArray>>(this)),
        progressBar(new QProgressBar(this)),
        buttonBox(nullptr)
  {
    setupCommonStyles();
    connect(dhWatcher, &QFutureWatcher<QList<QByteArray>>::finished,
            this, &BaseChatDialog::handleDHGenerationFinished);
  }

  ~BaseChatDialog() override {
    if (dhWatcher->isRunning()) {
      dhWatcher->cancel();
      dhWatcher->waitForFinished();
    }
    delete dhWatcher;
  }

  void setupCommonStyles() {
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

  void setupDHGeneration(int bitLength = 1024) {
    progressBar->setVisible(true);
    progressBar->setRange(0, 0);
    progressBar->setFormat("Генерация ключей Диффи-Хеллмана...");

    QFuture<QList<QByteArray>> future = QtConcurrent::run(generateDHParameters, bitLength, 0.95);
    dhWatcher->setFuture(future);
  }

  virtual void handleDHGenerationFinished() {
    QList<QByteArray> results = dhWatcher->result();

    if (results.size() >= 3) {
      dhPrime = results[0];
      dhGenerator = results[1];
      dhPublicKey = results[2];
      qDebug() << "DH параметры успешно сгенерированы";
      qDebug() << "Prime size:" << dhPrime.size() << "bytes";
      qDebug() << "Generator size:" << dhGenerator.size() << "bytes";
      qDebug() << "Public key size:" << dhPublicKey.size() << "bytes";
    } else {
      qCritical() << "Ошибка генерации DH параметров";
      QMessageBox::critical(this, "Ошибка",
                            "Не удалось сгенерировать параметры Диффи-Хеллмана. Попробуйте еще раз.");
      clearDHParameters();
    }

    progressBar->setVisible(false);
    validateForm();
  }

  void clearDHParameters() {
    dhPrime.clear();
    dhGenerator.clear();
    dhPublicKey.clear();
  }

  virtual void validateForm() = 0;

 public:
  QByteArray getPrime() const { return dhPrime; }
  QByteArray getGenerator() const { return dhGenerator; }
  QByteArray getPublicKey() const { return dhPublicKey; }
};

class ChoiceDialog : public QDialog {
  Q_OBJECT
 public:
  explicit ChoiceDialog(QWidget* parent = nullptr) : QDialog(parent) {
    setupUi();
    connectSignals();
  }

 signals:
  void createChatRequested();
  void joinChatRequested();

 private:
  void setupUi() {
    setWindowTitle("🐱 Новый чат");
    setFixedSize(350, 220);

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(30, 20, 30, 20);
    layout->setSpacing(25);

    QLabel* titleLabel = new QLabel("🐾 Выберите тип чата");
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 16pt; font-weight: 600; color: #e4e6eb;");
    layout->addWidget(titleLabel);

    QPushButton* createButton = new QPushButton("🐱 Создать новый чат");
    createButton->setStyleSheet("font-size: 12pt; padding: 12px;");
    layout->addWidget(createButton);

    QPushButton* joinButton = new QPushButton("🔗 Присоединиться к чату");
    joinButton->setStyleSheet("font-size: 12pt; padding: 12px;");
    layout->addWidget(joinButton);

    this->createButton = createButton;
    this->joinButton = joinButton;
  }

  void connectSignals() {
    connect(createButton, &QPushButton::clicked, this, [this]() {
      emit createChatRequested();
      accept();
    });

    connect(joinButton, &QPushButton::clicked, this, [this]() {
      emit joinChatRequested();
      accept();
    });
  }

  QPushButton* createButton;
  QPushButton* joinButton;
};


class CreateChatDialog : public BaseChatDialog {
  Q_OBJECT
 public:
  explicit CreateChatDialog(QWidget* parent = nullptr) : BaseChatDialog(parent) {
    setupUi();
    connectSignals();
    setupDHGeneration();
    generateRandomIV();
  }

  QString getContactUsername() const { return contactUsernameEdit->text().trimmed(); }
  int getAlgorithm() const { return algorithmCombo->currentData().toInt(); }
  int getMode() const { return modeCombo->currentData().toInt(); }
  int getPadding() const { return paddingCombo->currentData().toInt(); }
  QByteArray getIV() const { return QByteArray::fromHex(ivEdit->text().toLatin1()); }

 private:
  QLineEdit* contactUsernameEdit;
  QComboBox* algorithmCombo;
  QComboBox* modeCombo;
  QComboBox* paddingCombo;
  QLineEdit* ivEdit;
  QPushButton* generateIVButton;

  void setupUi() {
    setWindowTitle("🐱 Создание нового чата");
    setFixedSize(500, 450);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 15, 20, 15);
    mainLayout->setSpacing(15);

    QGroupBox* contactGroup = new QGroupBox("😺 Контакт для чата");
    QVBoxLayout* contactLayout = new QVBoxLayout(contactGroup);

    contactUsernameEdit = new QLineEdit();
    contactUsernameEdit->setPlaceholderText("Введите имя пользователя...");
    contactLayout->addWidget(contactUsernameEdit);
    mainLayout->addWidget(contactGroup);

    QGroupBox* encryptionGroup = new QGroupBox("🔐 Параметры шифрования");
    QGridLayout* encryptionLayout = new QGridLayout(encryptionGroup);
    encryptionLayout->setVerticalSpacing(12);

    encryptionLayout->addWidget(new QLabel("Алгоритм:"), 0, 0);
    algorithmCombo = new QComboBox();
    algorithmCombo->addItem("LOKI97", 0);
    algorithmCombo->addItem("RC6", 1);
    encryptionLayout->addWidget(algorithmCombo, 0, 1);

    encryptionLayout->addWidget(new QLabel("Режим:"), 1, 0);
    modeCombo = new QComboBox();
    modeCombo->addItem("ECB", 0);
    modeCombo->addItem("CBC", 1);
    modeCombo->addItem("PCBC", 2);
    modeCombo->addItem("CFB", 3);
    modeCombo->addItem("OFB", 4);
    modeCombo->addItem("CTR", 5);
    modeCombo->addItem("RANDOM_DELTA", 6);
    encryptionLayout->addWidget(modeCombo, 1, 1);

    encryptionLayout->addWidget(new QLabel("Дополнение:"), 2, 0);
    paddingCombo = new QComboBox();
    paddingCombo->addItem("ZEROS", 0);
    paddingCombo->addItem("ANSI_X923", 1);
    paddingCombo->addItem("PKCS7", 2);
    paddingCombo->addItem("ISO10126", 3);
    encryptionLayout->addWidget(paddingCombo, 2, 1);

    encryptionLayout->addWidget(new QLabel("Вектор инициализации:"), 3, 0);
    auto ivLayout = new QHBoxLayout();
    ivEdit = new QLineEdit();
    ivEdit->setReadOnly(true);
    ivEdit->setPlaceholderText("Случайно сгенерированный IV...");
    generateIVButton = new QPushButton("🎲 Сгенерировать");
    generateIVButton->setFixedWidth(120);
    ivLayout->addWidget(ivEdit, 4);
    ivLayout->addWidget(generateIVButton, 1);
    encryptionLayout->addLayout(ivLayout, 3, 1);

    mainLayout->addWidget(encryptionGroup);

    mainLayout->addWidget(progressBar);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    mainLayout->addWidget(buttonBox);

    validateForm();
  }

  void connectSignals() {
    connect(generateIVButton, &QPushButton::clicked, this, &CreateChatDialog::generateRandomIV);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &CreateChatDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &CreateChatDialog::reject);

    auto validate = [this]() { validateForm(); };
    connect(contactUsernameEdit, &QLineEdit::textChanged, this, validate);
    connect(algorithmCombo, &QComboBox::currentIndexChanged, this, validate);
    connect(modeCombo, &QComboBox::currentIndexChanged, this, validate);
    connect(paddingCombo, &QComboBox::currentIndexChanged, this, validate);
    connect(ivEdit, &QLineEdit::textChanged, this, validate);
  }

  void generateRandomIV() {
    QByteArray iv(16, 0);
    for (int i = 0; i < iv.size(); ++i) {
      iv[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    }
    ivEdit->setText(iv.toHex().toUpper());
  }

  void validateForm() override {
    bool valid = !getContactUsername().isEmpty() &&
                 !ivEdit->text().isEmpty() &&
                 !dhPrime.isEmpty() &&
                 !dhGenerator.isEmpty() &&
                 !dhPublicKey.isEmpty();

    buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);

    QString tooltip = valid ? "Все параметры заполнены корректно" :
                          "Заполните все обязательные поля для продолжения";
    buttonBox->button(QDialogButtonBox::Ok)->setToolTip(tooltip);
  }
};


class JoinChatDialog : public BaseChatDialog {
  Q_OBJECT
 public:
  explicit JoinChatDialog(QWidget* parent = nullptr) : BaseChatDialog(parent) {
    setupUi();
    connectSignals();
    setupDHGeneration(512);
  }

  QString getChatId() const { return chatIdEdit->text().trimmed(); }

 private:
  QLineEdit* chatIdEdit;

  void setupUi() {
    setWindowTitle("🔗 Присоединение к чату");
    setFixedSize(450, 200);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 15, 20, 15);
    mainLayout->setSpacing(15);

    QGroupBox* chatGroup = new QGroupBox("💬 Информация о чате");
    QVBoxLayout* chatLayout = new QVBoxLayout(chatGroup);

    chatLayout->addWidget(new QLabel("ID чата:"));
    chatIdEdit = new QLineEdit();
    chatIdEdit->setPlaceholderText("Введите идентификатор чата...");
    chatLayout->addWidget(chatIdEdit);

    mainLayout->addWidget(chatGroup);

    mainLayout->addWidget(progressBar);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    mainLayout->addWidget(buttonBox);

    validateForm();
  }

  void connectSignals() {
    connect(buttonBox, &QDialogButtonBox::accepted, this, &JoinChatDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &JoinChatDialog::reject);
    connect(chatIdEdit, &QLineEdit::textChanged, this, &JoinChatDialog::validateForm);
  }

  void validateForm() override {
    bool valid = !getChatId().isEmpty() &&
                 !dhPrime.isEmpty() &&
                 !dhGenerator.isEmpty() &&
                 !dhPublicKey.isEmpty();

    buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);

    QString tooltip = valid ? "Готово к присоединению к чату" :
                          "Введите ID чата и дождитесь генерации ключей";
    buttonBox->button(QDialogButtonBox::Ok)->setToolTip(tooltip);
  }

  void handleDHGenerationFinished() override {
    BaseChatDialog::handleDHGenerationFinished();
    qDebug() << "DH параметры для присоединения успешно сгенерированы";
  }
};
