#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QObject>
#include <QSettings>

class SessionManager : public QObject {
  Q_OBJECT
 public:
  static SessionManager& instance();

  void setSessionData(const QString& token, const QString& username);
  QString sessionToken() const;
  QString username() const;
  bool isLoggedIn() const;
  void clearSession();

  void setUserData(const QString& key, const QVariant& value);
  QVariant userData(const QString& key) const;

 signals:
  void sessionChanged(bool loggedIn);
  // void logoutRequested();

 private:
  SessionManager() = default;
  ~SessionManager() = default;

  SessionManager(const SessionManager&) = delete;
  SessionManager& operator=(const SessionManager&) = delete;
};

#endif  // SESSIONMANAGER_H
