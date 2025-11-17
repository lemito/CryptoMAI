#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "contactsdialog.h"
#include "logindialog.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

 public slots:
  void onLoginSuccess(const QString& username, const QString& token);
  void onLogout();

 private:
  Ui::MainWindow *ui;
  ContactsDialog *contactsDialog;
  QLabel *m_userLabel;
  QPushButton *m_logoutButton;

  void setupUserInterface();
  void updateUserInfo();

 private slots:
  void showContactsDialog() const;
  void on_userStatusButton_clicked();
};
#endif  // MAINWINDOW_H
