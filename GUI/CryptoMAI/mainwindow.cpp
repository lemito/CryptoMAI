#include "mainwindow.h"

#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      contactsDialog(new ContactsDialog(this)) {
  ui->setupUi(this);

  connect(ui->actionShowContacts, &QAction::triggered, this,
          &MainWindow::showContactsDialog);


}

MainWindow::~MainWindow() { delete ui; }


void MainWindow::showContactsDialog() {
  contactsDialog->show();
  contactsDialog->raise();
  contactsDialog->activateWindow();
}
