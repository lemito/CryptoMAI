#include "joinchatdialog.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

JoinChatDialog::JoinChatDialog(QWidget* parent) : BaseChatDialog(parent) {
  setupUi();
  connectSignals();
  setupDHGeneration(512);
}

void JoinChatDialog::setupUi() {
  setWindowTitle("Присоединение к чату");
  setFixedSize(450, 200);

  auto* mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(20, 15, 20, 15);
  mainLayout->setSpacing(15);

  auto* chatGroup = new QGroupBox("Информация о чате");
  auto* chatLayout = new QFormLayout();

  chatIdEdit = new QLineEdit;
  chatIdEdit->setPlaceholderText("Введите ID чата");
  chatLayout->addRow("ID чата:", chatIdEdit);

  mainLayout->addWidget(progressBar);
  progressBar->setVisible(false);

  chatGroup->setLayout(chatLayout);
  mainLayout->addWidget(chatGroup);

  buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
  mainLayout->addWidget(buttonBox);

  setLayout(mainLayout);
}

void JoinChatDialog::connectSignals() {
  connect(buttonBox, &QDialogButtonBox::accepted, this,
          &JoinChatDialog::accept);
  connect(buttonBox, &QDialogButtonBox::rejected, this,
          &JoinChatDialog::reject);
  connect(chatIdEdit, &QLineEdit::textChanged, this,
          &JoinChatDialog::validateForm);
}

void JoinChatDialog::validateForm() {
  bool valid = !getChatId().isEmpty() && dhPublicKey > 0;

  buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
}

void JoinChatDialog::handleDHGenerationFinished() {
  BaseChatDialog::handleDHGenerationFinished();
  qDebug() << "DH параметры для присоединения успешно сгенерированы";
}

auto JoinChatDialog::getChatId() const -> QString {
  return chatIdEdit->text().trimmed();
}

auto JoinChatDialog::getPrime() const -> const BI& { return dhPrime; }

auto JoinChatDialog::getGenerator() const -> const BI& { return dhGenerator; }

auto JoinChatDialog::getPublicKey() const -> const BI& { return dhPublicKey; }

auto JoinChatDialog::getPrivateKey() const -> const BI& { return dhPrivateKey; }
