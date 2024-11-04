#ifndef BEN_AFK_H
#define BEN_AFK_H

#include <QWidget>
#include <QTcpSocket>
#include <QPushButton>
#include <QTextEdit>
#include <QLineEdit>
#include <QLabel>

class Ben_AFK : public QWidget
{
    Q_OBJECT

public:
    Ben_AFK(QWidget *parent = nullptr);
    ~Ben_AFK();

private slots:
    void connectToDaemon();
    void sendCommand();
    void readResponse();
    void handleDisconnect();

private:
    QTcpSocket *socket;
    QPushButton *connectButton;
    QPushButton *sendButton;
    QLineEdit *inputField;
    QTextEdit *outputDisplay;
    QLabel *statusLabel;
    bool isConnected;
};

#endif
