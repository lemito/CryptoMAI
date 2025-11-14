#include "mainwindow.h"

#include "src/GUI//ui_mainwindow.h"

#include "lib.h"

import cypher;

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
