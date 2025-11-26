#ifndef JOINCHATDIALOG_H
#define JOINCHATDIALOG_H

#include "dialogutils.h"
#include <QDialog>

class QLineEdit;

class JoinChatDialog : public BaseChatDialog {
  Q_OBJECT

 public:
  explicit JoinChatDialog(QWidget* parent = nullptr);
  QString getChatId() const;

 private:
  void setupUi();
  void connectSignals();
  void validateForm() override;
  void handleDHGenerationFinished() override;

  QLineEdit* chatIdEdit;
};

#endif // JOINCHATDIALOG_H
