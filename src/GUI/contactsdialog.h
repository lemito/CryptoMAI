#ifndef CONTACTSDIALOG_H
#define CONTACTSDIALOG_H

#include <QDialog>

namespace Ui {
class ContactsDialog;
}

class ContactsDialog : public QDialog {
  Q_OBJECT

 public:
  explicit ContactsDialog(QWidget *parent = nullptr);
  ~ContactsDialog();

 private:
  Ui::ContactsDialog *ui;
};

#endif  // CONTACTSDIALOG_H
