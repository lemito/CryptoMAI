#include "sessionmanager.h"

SessionManager& SessionManager::instance() {
  static SessionManager instance;
  return instance;
}

SessionManager::SessionManager() {
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

QString SessionManager::sessionToken() const {
  return m_settings->value("session/token").toString();
}

QString SessionManager::username() const {
  return m_settings->value("session/username").toString();
}

bool SessionManager::isLoggedIn() const { return !sessionToken().isEmpty(); }

void SessionManager::clearSession() {
  m_settings->remove("session");
  m_settings->sync();

  // Испускаем сигнал только если действительно изменилось состояние
  emit sessionChanged(false);
  // m_settings->remove("session");
  // m_settings->sync();
  // emit sessionChanged(false);
}

void SessionManager::setUserData(const QString& key, const QVariant& value) {
  m_settings->setValue("userdata/" + key, value);
  m_settings->sync();
}

QVariant SessionManager::userData(const QString& key) const {
  return m_settings->value("userdata/" + key);
}
