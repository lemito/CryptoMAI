#include "contactsdialog.h"

#include "src/GUI/ui_contactsdialog.h"

ContactsDialog::ContactsDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::ContactsDialog) {
  ui->setupUi(this);
}

ContactsDialog::~ContactsDialog() { delete ui; }
