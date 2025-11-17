#include <QApplication>
#include <QLocale>
#include <QTranslator>

#include "mainwindow.h"

int main(int argc, char *argv[]) {
  QApplication a(argc, argv);

  QTranslator translator;
  const QStringList uiLanguages = QLocale::system().uiLanguages();
  for (const QString &locale : uiLanguages) {
    const QString baseName = "CryptoMAI_" + QLocale(locale).name();
    if (translator.load(":/i18n/" + baseName)) {
      a.installTranslator(&translator);
      break;
    }
  }
  bool hasValidSession = SessionManager::instance().isLoggedIn();

  MainWindow w;
  LoginDialog loginDialog;

  if (hasValidSession) {
    w.show();
  } else {
    loginDialog.show();
  }

  QObject::connect(&loginDialog, &LoginDialog::loginSuccess,
                   &w, &MainWindow::onLoginSuccess);

  QObject::connect(&SessionManager::instance(), &SessionManager::sessionChanged,
                   [&loginDialog, &w](bool loggedIn) {
                     if (loggedIn) {
                       loginDialog.hide();
                       w.show();
                     } else {
                       w.hide();
                       loginDialog.show();
                     }
                   });

  return a.exec();
}
