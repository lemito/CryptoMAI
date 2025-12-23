#ifndef JOINCHATDIALOG_H
#define JOINCHATDIALOG_H

#include <QDialog>

#include "dialogutils.h"

class QLineEdit;

class JoinChatDialog : public BaseChatDialog {
  Q_OBJECT

 public:
  explicit JoinChatDialog(QWidget* parent = nullptr);

  [[nodiscard]] auto getChatId() const -> QString;
  [[nodiscard]] auto getPrime() const -> const BI&;
  [[nodiscard]] auto getGenerator() const -> const BI&;
  [[nodiscard]] auto getPublicKey() const -> const BI&;
  [[nodiscard]] auto getPrivateKey() const -> const BI&;

 public slots:
  void validateForm() override;
  void handleDHGenerationFinished() override;

 private:
  void setupUi();
  void connectSignals();

  QLineEdit* chatIdEdit;
};

#endif  // JOINCHATDIALOG_H
