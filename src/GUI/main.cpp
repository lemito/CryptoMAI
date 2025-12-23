#include <QApplication>
#include <QLocale>
#include <QTimer>
#include <QTranslator>
#include <memory>
#include <QDebug>

#include "databasemanager.h"
#include "logindialog.h"
#include "mainwindow.h"
#include "sessionmanager.h"

auto main(int argc, char* argv[]) -> int {
  QApplication app(argc, argv);
  app.setQuitOnLastWindowClosed(true);

  QTranslator translator;
  const QStringList uiLanguages = QLocale::system().uiLanguages();
  for (const QString& locale : uiLanguages) {
    const QString baseName = "CryptoMAI_" + QLocale(locale).name();
    if (translator.load(":/i18n/" + baseName)) {
      app.installTranslator(&translator);
      break;
    }
  }

  std::unique_ptr<MainWindow> mainWindow = nullptr;
  std::unique_ptr<LoginDialog> loginDialog = nullptr;
  bool isShuttingDown = false;

  auto showMainWindow = [&]() -> void {
    if (isShuttingDown) {
      return;
    }

    try {
      if (mainWindow) {
        qDebug() << "Уничтожение старого MainWindow...";
        mainWindow.reset();
      }

      qDebug() << "Создание нового MainWindow...";
      mainWindow = std::make_unique<MainWindow>();

      if (loginDialog) {
        loginDialog->hide();
      }

      mainWindow->show();
      mainWindow->raise();
      mainWindow->activateWindow();

      qDebug() << "Главное окно показано";
    } catch (const std::exception& e) {
      qCritical() << "Ошибка при показе главного окна:" << e.what();
    }
  };

  auto showLoginDialog = [&]() -> void {
    if (isShuttingDown) {
      return;
    }

    try {
      if (mainWindow) {
        qDebug() << "Выход: уничтожение MainWindow...";
        mainWindow.reset();
      }

      if (!loginDialog) {
        qDebug() << "Создание диалога входа...";
        loginDialog = std::make_unique<LoginDialog>();
        QObject::connect(
            loginDialog.get(), &LoginDialog::loginSuccess, &app,
            [&]() -> void { showMainWindow(); }, Qt::QueuedConnection);
      }

      loginDialog->show();
      loginDialog->raise();
      loginDialog->activateWindow();

      qDebug() << "Окно входа показано";
    } catch (const std::exception& e) {
      qCritical() << "Ошибка при показе окна входа:" << e.what();
    }
  };

  QObject::connect(
      &SessionManager::instance(), &SessionManager::sessionChanged, &app,
      [&](bool loggedIn) -> void {
        if (isShuttingDown) {
          return;
        }

        qDebug() << "Изменение сессии, loggedIn =" << loggedIn;
        if (loggedIn) {
          if (mainWindow != nullptr) {
            showMainWindow();
          }
        } else {
          showLoginDialog();
        }
      },
      Qt::QueuedConnection);

  if (SessionManager::instance().isLoggedIn()) {
    showMainWindow();
  } else {
    showLoginDialog();
  }

  const auto res = app.exec();

  isShuttingDown = true;

  if (mainWindow) {
    mainWindow->hide();
    mainWindow.reset();
  }
  if (loginDialog) {
    loginDialog->hide();
    loginDialog.reset();
  }

  DatabaseManager::destroyInstance();

  return res;
}
