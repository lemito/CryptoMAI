#include "sessionmanager.h"

auto SessionManager::instance() -> SessionManager& {
  static SessionManager instance;
  return instance;
}

SessionManager::SessionManager() {
  qDebug() << "SessionManager инициализирован";
  m_instanceId = QUuid::createUuid().toString();
  m_settings =
      std::make_unique<QSettings>("lemito", "MeowChat_" + m_instanceId);
}

void SessionManager::setSessionData(const QString& token,
                                    const QString& username) {
  m_settings->setValue("session/token", token);
  m_settings->setValue("session/username", username);
  m_settings->sync();
  emit sessionChanged(true);
}

auto SessionManager::sessionToken() const -> QString {
  const auto res = m_settings->value("session/token").toString();
  if (res.isEmpty()) {
    qCritical() << "session/token подозрительно пуст!!!!";
  }
  return res;
}

auto SessionManager::username() const -> QString {
  const auto res = m_settings->value("session/username").toString();
  if (res.isEmpty()) {
    qCritical() << "session/username подозрительно пуст!!!!";
  }
  return res;
}

auto SessionManager::isLoggedIn() const -> bool {
  return !sessionToken().isEmpty();
}

void SessionManager::clearSession() {
  m_settings->remove("session");
  m_settings->sync();

  emit sessionChanged(false);
}

void SessionManager::setUserData(const QString& key, const QVariant& value) {
  m_settings->setValue("userdata/" + key, value);
  m_settings->sync();
}

auto SessionManager::userData(const QString& key) const -> QVariant {
  return m_settings->value("userdata/" + key);
}
