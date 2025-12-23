#include "stickerpickerdialog.h"
#include <QQuickWidget>
#include <QQmlEngine>
#include <QQuickItem>
#include <QVBoxLayout>
#include <QTimer>
#include <QDebug>
#include <QApplication>

StickerPickerDialog::StickerPickerDialog(QWidget* parent)
    : QQuickWindow() {
  setFlags(Qt::Popup | Qt::FramelessWindowHint | Qt::NoDropShadowWindowHint);

  setColor(QColor(Qt::transparent));

  setWidth(400);
  setHeight(300);

  setupQML();
  }

void StickerPickerDialog::setupQML() {
  auto* engine = new QQmlEngine(this);
  QQmlComponent component(engine, QUrl("qrc:/dialogs/StickerPicker.qml"));

  if (component.isError()) {
    qDebug() << "QML Ошибки:" << component.errors();
    return;
  }

  auto* root = component.create();
  if (root == nullptr) {
    qCritical() << "Не удалось создать QML компонент";
    return;
  }

  auto* item = qobject_cast<QQuickItem*>(root);
  if (item != nullptr) {
    item->setParentItem(contentItem());

    connect(root, SIGNAL(stickerSelected(QString)),
            this, SLOT(onStickerSelected(QString)));
  }
}

void StickerPickerDialog::showAtPosition(const QPoint& pos) {
  setPosition(pos.x(), pos.y() - height() - 5);
  show();
  raise();
  requestActivate();
  setVisible(true);
}

void StickerPickerDialog::onStickerSelected(const QString& stickerCode) {
  emit stickerSelected(stickerCode);
}
