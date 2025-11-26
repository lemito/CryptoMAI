#ifndef CHOICEDIALOG_H
#define CHOICEDIALOG_H

#include <QDialog>

class QPushButton;
class QVBoxLayout;
class QLabel;

class ChoiceDialog : public QDialog {
  Q_OBJECT

 public:
  explicit ChoiceDialog(QWidget* parent = nullptr);

 signals:
  void createChatRequested();
  void joinChatRequested();

 private:
  void setupUi();
  void connectSignals();

  QPushButton* createButton;
  QPushButton* joinButton;
};

#endif