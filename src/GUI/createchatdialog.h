#ifndef CREATECHATDIALOG_H
#define CREATECHATDIALOG_H

#include "dialogutils.h"
#include <QDialog>

class QLineEdit;
class QComboBox;
class QPushButton;

class CreateChatDialog : public BaseChatDialog {
  Q_OBJECT

 public:
  explicit CreateChatDialog(QWidget* parent = nullptr);

  [[nodiscard]] auto getContactUsername() const -> QString;
  [[nodiscard]] auto getAlgorithm() const -> int;
  [[nodiscard]] auto getMode() const -> int;
  [[nodiscard]] auto getPadding() const -> int;
  [[nodiscard]] auto getIV() const -> QByteArray;

 private slots:
  void generateRandomIV();

 private:
  void setupUi();
  void connectSignals();
  void validateForm() override;

  QLineEdit* contactUsernameEdit;
  QComboBox* algorithmCombo;
  QComboBox* modeCombo;
  QComboBox* paddingCombo;
  QLineEdit* ivEdit;
  QPushButton* generateIVButton;
};

#endif // CREATECHATDIALOG_H
