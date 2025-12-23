#include "choicedialog.h"

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

ChoiceDialog::ChoiceDialog(QWidget* parent)
    : QDialog(parent), createButton(nullptr), joinButton(nullptr) {
  setupUi();
  connectSignals();
}

void ChoiceDialog::setupUi() {
  setWindowTitle("Новый чат");
  setFixedSize(350, 220);

  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(30, 20, 30, 20);
  layout->setSpacing(25);

  auto* createButton = new QPushButton("➕Создать новый чат");
  createButton->setStyleSheet("font-size: 12pt; padding: 12px;");
  layout->addWidget(createButton);

  auto* joinButton = new QPushButton("🔎Присоединиться к чату");
  joinButton->setStyleSheet("font-size: 12pt; padding: 12px;");
  layout->addWidget(joinButton);

  this->createButton = createButton;
  this->joinButton = joinButton;
}

void ChoiceDialog::connectSignals() {
  connect(createButton, &QPushButton::clicked, this, [this]() {
    emit createChatRequested();
    accept();
  });

  connect(joinButton, &QPushButton::clicked, this, [this]() {
    emit joinChatRequested();
    accept();
  });
}
