#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <QDialog>
#include <QMessageBox>

namespace Ui {
class LoginDialog;
}

class LoginDialog : public QDialog {
  Q_OBJECT

 public:
  explicit LoginDialog(QWidget *parent = nullptr);
  ~LoginDialog();

 private slots:
  void on_loginButton_clicked();
  void on_registerButton_clicked();
  void checkCredentials();

 private:
  Ui::LoginDialog *ui;

  const QString testLog = "meow";
  const QString testPass = "meow";
};

#endif  // LOGINDIALOG_H
