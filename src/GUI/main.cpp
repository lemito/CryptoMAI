#include <QApplication>
#include <QLocale>
#include <QTimer>
#include <QTranslator>
#include <memory>

#include "databasemanager.h"
#include "logindialog.h"
#include "mainwindow.h"
#include "sessionmanager.h"

auto main(int argc, char* argv[]) -> int {
  QApplication app(argc, argv);
  app.setQuitOnLastWindowClosed(false);

  QTranslator translator;
  const QStringList uiLanguages = QLocale::system().uiLanguages();
  for (const QString& locale : uiLanguages) {
    const QString baseName = "CryptoMAI_" + QLocale(locale).name();
    if (translator.load(":/i18n/" + baseName)) {
      app.installTranslator(&translator);
      break;
    }
  }

  std::unique_ptr<MainWindow> mainWindow;
  std::unique_ptr<LoginDialog> loginDialog;

  auto showMainWindow = [&]() {
    if (!mainWindow) {
      mainWindow = std::make_unique<MainWindow>();
    }
    if (loginDialog) {
      loginDialog->hide();
    }
    mainWindow->show();
    mainWindow->raise();
    mainWindow->activateWindow();
  };

  auto showLoginDialog = [&]() {
    if (!loginDialog) {
      loginDialog = std::make_unique<LoginDialog>();
      QObject::connect(loginDialog.get(), &LoginDialog::loginSuccess,
                       [&]() { showMainWindow(); });
    }
    if (mainWindow) {
      mainWindow->hide();
      QTimer::singleShot(100, [&]() { mainWindow.reset(); });
    }
    loginDialog->show();
    loginDialog->raise();
    loginDialog->activateWindow();
  };

  QObject::connect(&SessionManager::instance(), &SessionManager::sessionChanged,
                   [&](bool loggedIn) {
                     if (loggedIn) {
                       showMainWindow();
                     } else {
                       showLoginDialog();
                     }
                   });

  if (SessionManager::instance().isLoggedIn()) {
    showMainWindow();
  } else {
    showLoginDialog();
  }

  const auto res = app.exec();

  DatabaseManager::destroyInstance();

  return res;
}
