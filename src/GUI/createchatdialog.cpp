#include "createchatdialog.h"

#include <QComboBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRandomGenerator>
#include <QVBoxLayout>

CreateChatDialog::CreateChatDialog(QWidget* parent)
    : BaseChatDialog(parent),
      contactUsernameEdit(nullptr),
      algorithmCombo(nullptr),
      modeCombo(nullptr),
      paddingCombo(nullptr),
      ivEdit(nullptr),
      generateIVButton(nullptr) {
  setupUi();
  connectSignals();
  setupDHGeneration(512);
  generateRandomIV();
}

void CreateChatDialog::setupUi() {
  setWindowTitle("Создание нового чата");
  setFixedSize(500, 450);

  auto* mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(20, 15, 20, 15);
  mainLayout->setSpacing(15);

  auto* contactGroup = new QGroupBox("Контакт для чата");
  auto* contactLayout = new QVBoxLayout(contactGroup);

  contactUsernameEdit = new QLineEdit();
  contactUsernameEdit->setPlaceholderText("Введите имя пользователя...");
  contactLayout->addWidget(contactUsernameEdit);
  mainLayout->addWidget(contactGroup);

  auto* encryptionGroup = new QGroupBox("Параметры шифрования");
  auto* encryptionLayout = new QGridLayout(encryptionGroup);
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

  encryptionLayout->addWidget(new QLabel("Набивка:"), 2, 0);
  paddingCombo = new QComboBox();
  paddingCombo->addItem("ZEROS", 0);
  paddingCombo->addItem("ANSI_X923", 1);
  paddingCombo->addItem("PKCS7", 2);
  paddingCombo->addItem("ISO10126", 3);
  encryptionLayout->addWidget(paddingCombo, 2, 1);

  encryptionLayout->addWidget(new QLabel("Вектор инициализации:"), 3, 0);
  auto* ivLayout = new QHBoxLayout();
  ivEdit = new QLineEdit();
  ivEdit->setReadOnly(true);
  ivEdit->setPlaceholderText("Случайно сгенерированный IV...");
  generateIVButton = new QPushButton("Сгенерировать");
  generateIVButton->setFixedWidth(120);
  ivLayout->addWidget(ivEdit, 4);
  ivLayout->addWidget(generateIVButton, 1);
  encryptionLayout->addLayout(ivLayout, 3, 1);

  mainLayout->addWidget(encryptionGroup);

  mainLayout->addWidget(progressBar);

  buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  mainLayout->addWidget(buttonBox);

  validateForm();
}

void CreateChatDialog::connectSignals() {
  connect(generateIVButton, &QPushButton::clicked, this,
          &CreateChatDialog::generateRandomIV);
  connect(buttonBox, &QDialogButtonBox::accepted, this,
          &CreateChatDialog::accept);
  connect(buttonBox, &QDialogButtonBox::rejected, this,
          &CreateChatDialog::reject);

  auto validate = [this]() { validateForm(); };
  connect(contactUsernameEdit, &QLineEdit::textChanged, this, validate);
  connect(algorithmCombo, &QComboBox::currentIndexChanged, this, validate);
  connect(modeCombo, &QComboBox::currentIndexChanged, this, validate);
  connect(paddingCombo, &QComboBox::currentIndexChanged, this, validate);
  connect(ivEdit, &QLineEdit::textChanged, this, validate);
}

#define BYTE_MASK (0xFF)

void CreateChatDialog::generateRandomIV() {
  QByteArray iv(16, 0);
  for (int i = 0; i < iv.size(); ++i) {
    iv[i] =
        static_cast<char>(QRandomGenerator::global()->generate() & BYTE_MASK);
  }
  ivEdit->setText(iv.toHex().toUpper());
}

void CreateChatDialog::validateForm() {
  bool valid = !getContactUsername().isEmpty() && !ivEdit->text().isEmpty() &&
               dhPrime > 0 && dhGenerator > 0 && dhPublicKey > 0;

  buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
}

auto CreateChatDialog::getContactUsername() const -> QString {
  return contactUsernameEdit->text().trimmed();
}
auto CreateChatDialog::getAlgorithm() const -> int {
  return algorithmCombo->currentData().toInt();
}
auto CreateChatDialog::getMode() const -> int {
  return modeCombo->currentData().toInt();
}
auto CreateChatDialog::getPadding() const -> int {
  return paddingCombo->currentData().toInt();
}
auto CreateChatDialog::getIV() const -> QByteArray {
  return QByteArray::fromHex(ivEdit->text().toLatin1());
}
