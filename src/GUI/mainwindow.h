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

 private:
  Ui::MainWindow *ui;
  ContactsDialog *contactsDialog;

 private slots:
  void showContactsDialog() const;
};
#endif  // MAINWINDOW_H
