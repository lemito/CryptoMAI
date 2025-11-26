#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QObject>
#include <QSettings>
#include <QUuid>
#include <memory>

class SessionManager : public QObject {
  Q_OBJECT
 public:
  SessionManager(const SessionManager&) = delete;
  auto operator=(const SessionManager&) -> SessionManager& = delete;

  static auto instance() -> SessionManager&;

  void setSessionData(const QString& token, const QString& username);
  [[nodiscard]] auto sessionToken() const -> QString;
  [[nodiscard]] auto username() const -> QString;
  [[nodiscard]] auto isLoggedIn() const -> bool;
  void clearSession();

  void setUserData(const QString& key, const QVariant& value);
  [[nodiscard]] auto userData(const QString& key) const -> QVariant;

 signals:
  void sessionChanged(bool loggedIn);
  // void logoutRequested();

 private:
  SessionManager();
  ~SessionManager() = default;

  // QSettings* m_settings;
  std::unique_ptr<QSettings> m_settings;
  QString m_instanceId;
};

#endif  // SESSIONMANAGER_H
