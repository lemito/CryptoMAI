#include "registerdialog.h"

#include "src/GUI/ui_registerdialog.h"

RegisterDialog::RegisterDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::RegisterDialog) {
  ui->setupUi(this);
}

RegisterDialog::~RegisterDialog() { delete ui; }
