#include "contactsdialog.h"

#include <grpcpp/grpcpp.h>

#include <QCloseEvent>
#include <QDebug>
#include <QLabel>
#include <QMessageBox>
#include <QThread>

#include "contactlistitem.h"
#include "sessionmanager.h"
#include "ui_contactsdialog.h"
#include "utils.hpp"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

ContactsDialog::ContactsDialog(QWidget* parent)
    : QDialog(parent), ui(new Ui::ContactsDialog) {
  ui->setupUi(this);
  setupGrpcChannel();

  qDebug() << "старт окошка";
  if (SessionManager::instance().isLoggedIn()) {
    qDebug() << "вход есть и загрузка контактов началась";
    loadContacts();
    startContactUpdates();
  } else {
    qCritical() << "не авторизован";
  }
}

ContactsDialog::~ContactsDialog() {
  stopAllThreads();
  delete ui;
}

void ContactsDialog::stopAllThreads() {
  stopUpdates_ = true;

  if (updatesThread_.joinable()) {
    updatesThread_.join();
  }
}

void ContactsDialog::closeEvent(QCloseEvent* event) {
  qDebug() << "close";
  stopAllThreads();
  QDialog::closeEvent(event);
}

void ContactsDialog::setupGrpcChannel() {
  auto channel = grpc::CreateChannel("localhost:50051",
                                     grpc::InsecureChannelCredentials());
  contactsStub_ = chat::ContactService::NewStub(channel);
}

void ContactsDialog::onCloseButton_clicked() {
  stopAllThreads();
  this->accept();
}

void ContactsDialog::onAddContactButton_clicked() {
  QString username = ui->searchEdit->text().trimmed();
  if (username.isEmpty()) {
    QMessageBox::warning(this, "Ошибка", "Введите имя пользователя");
    return;
  }

  addContact(username);
  ui->searchEdit->clear();
}

void ContactsDialog::onSearchEdit_textChanged(const QString& text) {
  for (int i = 0; i < ui->contactsList->count(); ++i) {
    QListWidgetItem* item = ui->contactsList->item(i);
    auto* widget =
        qobject_cast<ContactListItem*>(ui->contactsList->itemWidget(item));

    if (widget != nullptr) {
      bool matches = text.isEmpty() ||
                     widget->username().contains(text, Qt::CaseInsensitive);
      item->setHidden(!matches);
    } else {
      item->setHidden(false);
    }
  }

  QString currentHeader;
  bool hasVisibleContacts = false;

  for (int i = ui->contactsList->count() - 1; i >= 0; --i) {
    QListWidgetItem* item = ui->contactsList->item(i);
    auto* widget =
        qobject_cast<ContactListItem*>(ui->contactsList->itemWidget(item));

    if (widget != nullptr) {
      if (!item->isHidden()) {
        hasVisibleContacts = true;
      }
    } else if (item->text().startsWith("⏳") || item->text().startsWith("😸") ||
               item->text().startsWith("❓")) {
      if (!hasVisibleContacts) {
        item->setHidden(true);
      }
      hasVisibleContacts = false;
    }
  }
}

void ContactsDialog::loadContacts() {
  if (!SessionManager::instance().isLoggedIn()) {
    clearContactsList();
    auto* item = new QListWidgetItem("Необходимо войти");
    item->setTextAlignment(Qt::AlignCenter);
    item->setFlags(Qt::NoItemFlags);
    ui->contactsList->addItem(item);
    return;
  }

  if (stopUpdates_) {
    return;
  }

  std::thread([this]() {
    if (stopUpdates_) {
      return;
    }

    ClientContext context;

    auto token = SessionManager::instance().sessionToken().toStdString();
    if (!token.empty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token);
    }

    google::protobuf::Empty request;
    std::unique_ptr<grpc::ClientReader<chat::ContactInfo>> reader(
        contactsStub_->GetContacts(&context, request));

    QList<ContactInfo> contacts;
    chat::ContactInfo contact;

    while (reader->Read(&contact)) {
      if (stopUpdates_) {
        reader->Finish();
        return;
      }

      ContactInfo info;
      info.username = QString::fromStdString(contact.username());
      info.status = QString::fromStdString(contact.status());
      info.requestId = QString::fromStdString(contact.request_id());
      contacts.append(info);
      qDebug() << "Loaded contact:" << info.username;
    }

    Status status = reader->Finish();

    if (!stopUpdates_) {
      QMetaObject::invokeMethod(
          this,
          [this, status, contacts]() -> void {
            if (status.ok()) {
              onContactsLoaded(contacts);
            } else {
              handleGrpcError(status, "загрузка контактов");
              if (status.error_code() == grpc::UNAUTHENTICATED) {
                stopUpdates_ = true;
              }
            }
          },
          Qt::QueuedConnection);
    }
  }).detach();
}

void ContactsDialog::addContact(const QString& username) {
  if (!SessionManager::instance().isLoggedIn()) {
    QMessageBox::warning(this, "Ошибка", "Необходимо войти в систему");
    return;
  }

  if (stopUpdates_) {
    return;
  }

  std::thread([this, username]() {
    if (stopUpdates_) {
      return;
    }

    chat::ContactRequest request;
    request.set_target_username(username.toStdString());

    ClientContext context;

    auto token = SessionManager::instance().sessionToken().toStdString();
    if (!token.empty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token);
    }

    chat::CommonResponse response;
    Status status = contactsStub_->AddContact(&context, request, &response);

    if (!stopUpdates_) {
      QMetaObject::invokeMethod(
          this,
          [this, status, response, username]() {
            if (status.ok()) {
              if (response.success()) {
                QMessageBox::information(
                    this, "Успех",
                    QString("Запрос на добавление %1 отправлен").arg(username));
                loadContacts();
              } else {
                QMessageBox::warning(
                    this, "Ошибка", QString::fromStdString(response.message()));
              }
            } else {
              handleGrpcError(status, "добавления контакта");
            }
          },
          Qt::QueuedConnection);
    }
  }).detach();
}

void ContactsDialog::handleContactRequest(const QString& requestId,
                                          bool approve) {
  if (!SessionManager::instance().isLoggedIn()) {
    QMessageBox::warning(this, "Ошибка", "Необходимо войти в систему");
    return;
  }

  if (stopUpdates_) {
    return;
  }

  std::thread([this, requestId, approve]() {
    if (stopUpdates_) {
      return;
    }

    chat::ContactActionRequest request;
    request.set_request_id(requestId.toStdString());
    request.set_approve(approve);

    ClientContext context;

    auto token = SessionManager::instance().sessionToken().toStdString();
    if (!token.empty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token);
    }

    chat::CommonResponse response;
    Status status =
        contactsStub_->HandleContactRequest(&context, request, &response);

    if (!stopUpdates_) {
      QMetaObject::invokeMethod(
          this,
          [this, status, response, approve]() {
            if (status.ok()) {
              if (response.success()) {
                QString action = approve ? "принят" : "отклонен";
                QMessageBox::information(
                    this, "Успех",
                    QString("Запрос на добавление %1").arg(action));
                loadContacts();
              } else {
                QMessageBox::warning(
                    this, "Ошибка", QString::fromStdString(response.message()));
              }
            } else {
              handleGrpcError(status, "обработки запроса контакта");
            }
          },
          Qt::QueuedConnection);
    }
  }).detach();
}

void ContactsDialog::onAcceptRequest(const QString& requestId) {
  qDebug() << "Принятие запроса:" << requestId;
  handleContactRequest(requestId, true);
}

void ContactsDialog::onRejectRequest(const QString& requestId) {
  qDebug() << "Отклонение запроса:" << requestId;
  handleContactRequest(requestId, false);
}

void ContactsDialog::onRemoveContact(const QString& username) {
  qDebug() << "Удаление контакта:" << username;

  if (!SessionManager::instance().isLoggedIn()) {
    QMessageBox::warning(this, "Ошибка", "Необходимо войти в систему");
    return;
  }

  int result = QMessageBox::question(
      this, "Удаление контакта",
      QString("Вы уверены, что хотите удалить контакт %1?").arg(username),
      QMessageBox::Yes | QMessageBox::No);

  if (result != QMessageBox::Yes) {
    return;
  }

  if (stopUpdates_) {
    return;
  }

  std::thread([this, username]() {
    if (stopUpdates_) {
      return;
    }

    chat::RemoveContactRequest request;
    request.set_contact_username(username.toStdString());

    ClientContext context;

    auto token = SessionManager::instance().sessionToken().toStdString();
    if (!token.empty()) {
      context.AddMetadata(SESSION_TOKEN_HEADER, token);
    }

    chat::CommonResponse response;
    Status status = contactsStub_->RemoveContact(&context, request, &response);

    if (!stopUpdates_) {
      QMetaObject::invokeMethod(
          this,
          [this, status, response, username]() {
            if (status.ok()) {
              if (response.success()) {
                QMessageBox::information(
                    this, "Успех", QString("Контакт %1 удален").arg(username));
                loadContacts();
              } else {
                QMessageBox::warning(
                    this, "Ошибка", QString::fromStdString(response.message()));
              }
            } else {
              handleGrpcError(status, "удаления контакта");
            }
          },
          Qt::QueuedConnection);
    }
  }).detach();
}

void ContactsDialog::onStartChat(const QString& username) {
  QMessageBox::information(this, "Чат",
                           QString("Открываем чат с %1...").arg(username));
}

void ContactsDialog::onContactsLoaded(const QList<ContactInfo>& contacts) {
  clearContactsList();

  if (contacts.isEmpty()) {
    auto* item = new QListWidgetItem("📭 Контакты не найдены");
    item->setTextAlignment(Qt::AlignCenter);
    item->setFlags(Qt::NoItemFlags);
    ui->contactsList->addItem(item);
    return;
  }

  QList<ContactInfo> pendingContacts;
  QList<ContactInfo> activeContacts;
  QList<ContactInfo> otherContacts;

  for (const auto& contact : contacts) {
    if (contact.status == "pending") {
      pendingContacts.append(contact);
    } else if (contact.status == "accepted" || contact.status == "active") {
      activeContacts.append(contact);
    } else {
      otherContacts.append(contact);
    }
  }

  if (!pendingContacts.isEmpty()) {
    addHeaderToContactsList("⏳ Входящие заявки");
    for (const auto& contact : pendingContacts) {
      addContactToContactsList(contact);
    }
  }

  if (!activeContacts.isEmpty()) {
    addHeaderToContactsList("😸 Мои контакты");
    for (const auto& contact : activeContacts) {
      addContactToContactsList(contact);
    }
  }

  if (!otherContacts.isEmpty()) {
    addHeaderToContactsList("❓ Другие контакты");
    for (const auto& contact : otherContacts) {
      addContactToContactsList(contact);
    }
  }
}

void ContactsDialog::clearContactsList() { ui->contactsList->clear(); }

void ContactsDialog::addHeaderToContactsList(const QString& headerText) {
  auto* headerItem = new QListWidgetItem(headerText);
  headerItem->setFlags(Qt::NoItemFlags);
  headerItem->setForeground(QBrush(QColor(96, 110, 139)));
  headerItem->setBackground(QBrush(QColor(241, 245, 249)));
  headerItem->setFont(QFont("Segoe UI", 10, QFont::Bold));
  headerItem->setSizeHint(QSize(0, 30));
  headerItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

  ui->contactsList->addItem(headerItem);
}

void ContactsDialog::addContactToContactsList(const ContactInfo& contact) {
  auto* itemWidget =
      new ContactListItem(contact.username, contact.status, contact.requestId);

  connect(itemWidget, &ContactListItem::acceptRequest, this,
          &ContactsDialog::onAcceptRequest);
  connect(itemWidget, &ContactListItem::rejectRequest, this,
          &ContactsDialog::onRejectRequest);
  connect(itemWidget, &ContactListItem::removeContact, this,
          &ContactsDialog::onRemoveContact);

  auto* item = new QListWidgetItem();
  item->setSizeHint(itemWidget->sizeHint());
  ui->contactsList->addItem(item);
  ui->contactsList->setItemWidget(item, itemWidget);
}

void ContactsDialog::onErrorOccurred(const QString& errorMessage) {
  QMessageBox::critical(this, "Ошибка", errorMessage);
}

void ContactsDialog::handleGrpcError(const grpc::Status& status,
                                     const QString& operation) {
  QString errorMessage;

  if (status.error_code() == grpc::UNAUTHENTICATED) {
    errorMessage = "Ошибка аутентификации. Возможно, сессия истекла.";
    SessionManager::instance().clearSession();
    stopAllThreads();
  } else if (status.error_code() == grpc::UNAVAILABLE) {
    errorMessage = "Сервер недоступен. Проверьте подключение.";
  } else {
    errorMessage = QString("Ошибка при операции %1: %2")
                       .arg(operation)
                       .arg(QString::fromStdString(status.error_message()));
  }

  onErrorOccurred(errorMessage);
}

void ContactsDialog::startContactUpdates() {
  if (!SessionManager::instance().isLoggedIn()) {
    return;
  }

  stopUpdates_ = false;
  updatesThread_ = std::thread([this]() {
    qDebug() << "Поток обновлений контактов запущен";

    while (!stopUpdates_.load()) {
      try {
        auto localContext = std::make_unique<grpc::ClientContext>();
        auto token = SessionManager::instance().sessionToken().toStdString();
        if (!token.empty()) {
          localContext->AddMetadata(SESSION_TOKEN_HEADER, token);
        }

        auto deadline =
            std::chrono::system_clock::now() + std::chrono::seconds(2);
        localContext->set_deadline(deadline);

        google::protobuf::Empty request;
        auto localReader = contactsStub_->SubscribeToContactUpdates(
            localContext.get(), request);

        chat::ContactUpdate update;
        bool readSuccessful = true;

        while (readSuccessful && !stopUpdates_.load()) {
          readSuccessful = localReader->Read(&update);
          if (readSuccessful && !stopUpdates_.load()) {
            QMetaObject::invokeMethod(
                this, [this, update]() { onContactUpdateReceived(update); },
                Qt::QueuedConnection);
          }
        }

        if (localReader) {
          try {
            localReader->Finish();
          } catch (const std::exception& e) {
            if (!stopUpdates_.load()) {
              qDebug() << "Ошибка при завершении reader:" << e.what();
            }
          }
        }

        if (stopUpdates_.load()) {
          break;
        }

        if (!stopUpdates_.load()) {
          qDebug() << "Переподключение потока обновлений через 3 секунды...";
          std::this_thread::sleep_for(std::chrono::seconds(3));
        }

      } catch (const std::exception& e) {
        if (!stopUpdates_.load()) {
          qDebug() << "Исключение в потоке обновлений:" << e.what();
          std::this_thread::sleep_for(std::chrono::seconds(3));
        }
      }
    }
    qDebug() << "Поток обновлений контактов завершен";
  });
}

void ContactsDialog::onContactUpdateReceived(
    const chat::ContactUpdate& update) {
  QString type = QString::fromStdString(update.type());
  QString username = QString::fromStdString(update.contact().username());
  QString status = QString::fromStdString(update.contact().status());
  QString requestId = QString::fromStdString(update.contact().request_id());

  qDebug() << "Статус контакта обновлен:" << type << "Юзер:" << username;

  if (type == "request") {
    QMessageBox::information(
        this, "Новый запрос",
        QString("Пользователь %1 хочет добавить вас в контакты").arg(username));
    loadContacts();
  } else if (type == "added" || type == "removed" || type == "status_changed") {
    loadContacts();
  }
}
