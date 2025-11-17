#include "sessionmanager.h"

SessionManager& SessionManager::instance()
{
  static SessionManager instance;
  return instance;
}

void SessionManager::setSessionData(const QString& token, const QString& username)
{
  QSettings settings;
  settings.setValue("session/token", token);
  settings.setValue("session/username", username);
  settings.sync();

  emit sessionChanged(true);
}

QString SessionManager::sessionToken() const
{
  QSettings settings;
  return settings.value("session/token").toString();
}

QString SessionManager::username() const
{
  QSettings settings;
  return settings.value("session/username").toString();
}

bool SessionManager::isLoggedIn() const
{
  return !sessionToken().isEmpty();
}

void SessionManager::clearSession()
{
  QSettings settings;
  settings.remove("session/token");
  settings.remove("session/username");
  settings.sync();

  emit sessionChanged(false);
}

void SessionManager::setUserData(const QString& key, const QVariant& value)
{
  QSettings settings;
  settings.setValue(QString("userdata/%1").arg(key), value);
  settings.sync();
}

QVariant SessionManager::userData(const QString& key) const
{
  QSettings settings;
  return settings.value(QString("userdata/%1").arg(key));
}
