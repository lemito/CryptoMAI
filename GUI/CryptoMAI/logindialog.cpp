#include "logindialog.h"

#include "ui_logindialog.h"

LoginDialog::LoginDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::LoginDialog) {
  ui->setupUi(this);

  setWindowTitle("Вход | MeowChat");

  ui->usernameEdit->setPlaceholderText("Введите логин");
  ui->passwordEdit->setPlaceholderText("Введите пароль");

  ui->passwordEdit->setEchoMode(QLineEdit::Password);

  connect(ui->loginButton, &QPushButton::clicked, this, &LoginDialog::on_loginButton_clicked);
  connect(ui->registerButton, &QPushButton::clicked, this, &LoginDialog::on_registerButton_clicked);

  connect(ui->usernameEdit, &QLineEdit::returnPressed, this, &LoginDialog::checkCredentials);
  connect(ui->passwordEdit, &QLineEdit::returnPressed, this, &LoginDialog::checkCredentials);

  ui->usernameEdit->setFocus();
}

LoginDialog::~LoginDialog() { delete ui; }

void LoginDialog::on_loginButton_clicked() {
  checkCredentials();
}

void LoginDialog::on_registerButton_clicked() {
  QMessageBox::information(this, "Регистрация",
                           "Функция регистрации будет реализована в будущем.\n"
                           "Пока используйте:\nЛогин: meow\nПароль: meow");
}

void LoginDialog::checkCredentials() {
  QString username = ui->usernameEdit->text().trimmed();
  QString password = ui->passwordEdit->text();

  if (username.isEmpty() || password.isEmpty()) {
    QMessageBox::warning(this, "Ошибка", "Заполните все поля!");
    ui->usernameEdit->setFocus();
    return;
  }

  if (username == testLog && password == testPass) {
    QMessageBox::information(this, "Успех", "Добро пожаловать в MeowChat!");
    accept();
  } else {
    QMessageBox::critical(this, "Ошибка",
                          "Неправильный логин или пароль!\n\n"
                          "Подсказка:\nЛогин: meow\nПароль: meow");

    ui->passwordEdit->clear();
    ui->passwordEdit->setFocus();
  }
}
