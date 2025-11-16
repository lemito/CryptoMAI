#include "mainwindow.h"

#include "cypher/SymmetricAlgorithms/cypher.hpp"
#include "src/GUI/ui_mainwindow.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      contactsDialog(new ContactsDialog(this)) {
  ui->setupUi(this);

  connect(ui->actionShowContacts, &QAction::triggered, this,
          &MainWindow::showContactsDialog);

  auto ctx = meow::cypher::symm::SymmetricCypherContext(
      {}, meow::cypher::symm::encryptionMode::ECB,
      meow::cypher::symm::paddingMode::PKCS7, std::nullopt);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::showContactsDialog() const {
  contactsDialog->show();
  contactsDialog->raise();
  contactsDialog->activateWindow();
}
