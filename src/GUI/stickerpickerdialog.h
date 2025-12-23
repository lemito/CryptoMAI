#ifndef STICKERPICKERDIALOG_H
#define STICKERPICKERDIALOG_H

#include <QQuickWindow>
#include <memory>

class StickerPickerDialog : public QQuickWindow {
  Q_OBJECT

 public:
  explicit StickerPickerDialog(QWidget* parent = nullptr);
  ~StickerPickerDialog() = default;

  void showAtPosition(const QPoint& pos);

 signals:
  void stickerSelected(const QString& stickerCode);

 private slots:
  void onStickerSelected(const QString& stickerCode);

 private:
  void setupQML();
};

#endif  // STICKERPICKERDIALOG_H
