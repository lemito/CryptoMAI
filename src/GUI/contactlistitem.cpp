#include "contactlistitem.h"

#include <QDebug>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

ContactListItem::ContactListItem(const QString& username, const QString& status,
                                 const QString& requestId, QWidget* parent)
    : QWidget(parent),
      m_username(username),
      m_status(status),
      m_requestId(requestId),
      m_avatarLabel(nullptr),
      m_nameLabel(nullptr),
      m_acceptButton(nullptr),
      m_rejectButton(nullptr),
      m_removeButton(nullptr) {
  qDebug() << "init" << username;
  setupUI();
  updateAppearance();
}

void ContactListItem::setupUI() {
  qDebug() << "setupUI" << m_username;

  auto* layout = new QHBoxLayout(this);
  layout->setContentsMargins(12, 8, 12, 8);
  layout->setSpacing(12);

  m_avatarLabel = new QLabel(this);
  m_avatarLabel->setFixedSize(36, 36);
  m_avatarLabel->setAlignment(Qt::AlignCenter);
  m_avatarLabel->setStyleSheet(
      "QLabel {"
      "    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3a86ff, "
      "stop:1 #5e60ce);"
      "    border-radius: 18px;"
      "    color: white;"
      "    font-weight: bold;"
      "    font-size: 14pt;"
      "    min-width: 36px;"
      "    min-height: 36px;"
      "}");

  auto* infoWidget = new QWidget(this);
  auto* infoLayout = new QVBoxLayout(infoWidget);
  infoLayout->setContentsMargins(0, 0, 0, 0);
  infoLayout->setSpacing(2);

  m_nameLabel = new QLabel(m_username, infoWidget);
  m_nameLabel->setStyleSheet(
      "font-weight: 600; color: #1e293b; font-size: 10pt;");
  m_nameLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  m_nameLabel->setMinimumWidth(120);

  infoLayout->addWidget(m_nameLabel);
  infoLayout->addStretch();

  if (m_status == "pending") {
    m_acceptButton = new QPushButton("✅", this);
    m_acceptButton->setFixedSize(28, 28);
    m_acceptButton->setToolTip("Принять заявку");
    m_acceptButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #10b981;"
        "    border-radius: 14px;"
        "    border: none;"
        "    color: white;"
        "    font-size: 12pt;"
        "    min-width: 28px;"
        "    min-height: 28px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #059669;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #047857;"
        "}");

    m_rejectButton = new QPushButton("❌", this);
    m_rejectButton->setFixedSize(28, 28);
    m_rejectButton->setToolTip("Отклонить заявку");
    m_rejectButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #ef4444;"
        "    border-radius: 14px;"
        "    border: none;"
        "    color: white;"
        "    font-size: 12pt;"
        "    min-width: 28px;"
        "    min-height: 28px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #dc2626;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #b91c1c;"
        "}");

    connect(m_acceptButton, &QPushButton::clicked, this,
            &ContactListItem::onAcceptClicked);
    connect(m_rejectButton, &QPushButton::clicked, this,
            &ContactListItem::onRejectClicked);
  } else {
    m_removeButton = new QPushButton("🗑️", this);
    m_removeButton->setFixedSize(28, 28);
    m_removeButton->setToolTip("Удалить контакт");
    m_removeButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #94a3b8;"
        "    border-radius: 14px;"
        "    border: none;"
        "    color: white;"
        "    font-size: 12pt;"
        "    min-width: 28px;"
        "    min-height: 28px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #ef4444;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #dc2626;"
        "}");

    connect(m_removeButton, &QPushButton::clicked, this,
            &ContactListItem::onRemoveClicked);
  }

  layout->addWidget(m_avatarLabel);
  layout->addWidget(infoWidget, 1);

  if (m_status == "pending") {
    layout->addWidget(m_acceptButton);
    layout->addWidget(m_rejectButton);
  } else {
    layout->addWidget(m_removeButton);
  }

  qDebug() << "ContactListItem " << m_username;
}

void ContactListItem::updateAppearance() {
  if (!m_username.isEmpty()) {
    QString avatarText = m_username.left(1).toUpper();
    m_avatarLabel->setText(avatarText);
  }
}

void ContactListItem::onAcceptClicked() {
  qDebug() << "Accepted " << m_requestId;
  emit acceptRequest(m_requestId);
}

void ContactListItem::onRejectClicked() {
  qDebug() << "Rejected " << m_requestId;
  emit rejectRequest(m_requestId);
}

void ContactListItem::onRemoveClicked() {
  qDebug() << "Removed " << m_username;
  emit removeContact(m_username);
}
