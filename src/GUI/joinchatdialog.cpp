#include "joinchatdialog.h"
#include <QLineEdit>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>

JoinChatDialog::JoinChatDialog(QWidget* parent) : BaseChatDialog(parent) {
  setupUi();
  connectSignals();
  setupDHGeneration(512);
}

void JoinChatDialog::setupUi() {
  setWindowTitle("🔗 Присоединение к чату");
  setFixedSize(450, 200);

  auto* mainLayout = new QVBoxLayout(this);
  mainLayout->setContentsMargins(20, 15, 20, 15);
  mainLayout->setSpacing(15);


}

void JoinChatDialog::connectSignals() {
  connect(buttonBox, &QDialogButtonBox::accepted, this, &JoinChatDialog::accept);
  connect(buttonBox, &QDialogButtonBox::rejected, this, &JoinChatDialog::reject);
  connect(chatIdEdit, &QLineEdit::textChanged, this, &JoinChatDialog::validateForm);
}

void JoinChatDialog::validateForm() {
  bool valid = !getChatId().isEmpty() &&
               !dhPrime.isEmpty() &&
               !dhGenerator.isEmpty() &&
               !dhPublicKey.isEmpty();

  buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
}

void JoinChatDialog::handleDHGenerationFinished() {
  BaseChatDialog::handleDHGenerationFinished();
  qDebug() << "DH параметры для присоединения успешно сгенерированы";
}

auto JoinChatDialog::getChatId() const -> QString { return chatIdEdit->text().trimmed(); }
