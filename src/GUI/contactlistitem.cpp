#include "contactlistitem.h"
#include <QHBoxLayout>
#include <QLabel>

ContactListItem::ContactListItem(const QString &username, const QString &status,
                                 const QString &requestId, QWidget *parent)
    : QWidget(parent)
      , m_username(username)
      , m_status(status)
      , m_requestId(requestId)
{
  setupUI();
  updateAppearance();
}

void ContactListItem::setupUI()
{
  QHBoxLayout *layout = new QHBoxLayout(this);
  layout->setContentsMargins(12, 8, 12, 8);
  layout->setSpacing(12);

  m_avatarLabel = new QLabel(this);
  m_avatarLabel->setFixedSize(36, 36);
  m_avatarLabel->setAlignment(Qt::AlignCenter);
  m_avatarLabel->setStyleSheet(
      "QLabel {"
      "    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3a86ff, stop:1 #5e60ce);"
      "    border-radius: 18px;"
      "    color: white;"
      "    font-weight: bold;"
      "    font-size: 14pt;"
      "    min-width: 36px;"
      "    min-height: 36px;"
      "}"
      );

  QWidget *infoWidget = new QWidget(this);
  QVBoxLayout *infoLayout = new QVBoxLayout(infoWidget);
  infoLayout->setContentsMargins(0, 0, 0, 0);
  infoLayout->setSpacing(2);

  m_nameLabel = new QLabel(m_username, infoWidget);
  m_nameLabel->setStyleSheet("font-weight: 600; color: #1e293b; font-size: 10pt;");
  m_nameLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  m_nameLabel->setMinimumWidth(120);
  // m_nameLabel->setElideMode(Qt::ElideRight);

  m_statusLabel = new QLabel(infoWidget);
  m_statusLabel->setStyleSheet("color: #64748b; font-size: 9pt;");
  // m_statusLabel->setElideMode(Qt::ElideRight);

  infoLayout->addWidget(m_nameLabel);
  infoLayout->addWidget(m_statusLabel);
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
        "}"
        );

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
        "}"
        );

    connect(m_acceptButton, &QPushButton::clicked, this, &ContactListItem::onAcceptClicked);
    connect(m_rejectButton, &QPushButton::clicked, this, &ContactListItem::onRejectClicked);
  } else {
    m_chatButton = new QPushButton("💬", this);
    m_chatButton->setFixedSize(28, 28);
    m_chatButton->setToolTip("Начать чат");
    m_chatButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #3a86ff;"
        "    border-radius: 14px;"
        "    border: none;"
        "    color: white;"
        "    font-size: 12pt;"
        "    min-width: 28px;"
        "    min-height: 28px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #2a75f0;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #205fcc;"
        "}"
        );

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
        "}"
        );

    connect(m_chatButton, &QPushButton::clicked, this, &ContactListItem::onChatClicked);
    connect(m_removeButton, &QPushButton::clicked, this, &ContactListItem::onRemoveClicked);
  }

  layout->addWidget(m_avatarLabel);
  layout->addWidget(infoWidget, 1);

  if (m_status == "pending") {
    layout->addWidget(m_acceptButton);
    layout->addWidget(m_rejectButton);
  } else {
    layout->addWidget(m_chatButton);
    layout->addWidget(m_removeButton);
  }
}

void ContactListItem::updateAppearance()
{
  if (!m_username.isEmpty()) {
    QString avatarText = m_username.left(1).toUpper();
    m_avatarLabel->setText(avatarText);
  }

  if (m_status == "pending") {
    m_statusLabel->setText("⏳ Ожидает подтверждения");
    m_statusLabel->setStyleSheet("color: #f59e0b; font-size: 9pt;");
  } else if (m_status == "accepted" || m_status == "active") {
    m_statusLabel->setText("😸 В сети");
    m_statusLabel->setStyleSheet("color: #10b981; font-size: 9pt;");
  } else if (m_status == "offline") {
    m_statusLabel->setText("😼 Не в сети");
    m_statusLabel->setStyleSheet("color: #64748b; font-size: 9pt;");
  } else {
    m_statusLabel->setText(m_status);
  }
}

void ContactListItem::onAcceptClicked()
{
  emit acceptRequest(m_requestId);
}

void ContactListItem::onRejectClicked()
{
  emit rejectRequest(m_requestId);
}

void ContactListItem::onRemoveClicked()
{
  emit removeContact(m_username);
}

void ContactListItem::onChatClicked()
{
  emit startChat(m_username);
}
