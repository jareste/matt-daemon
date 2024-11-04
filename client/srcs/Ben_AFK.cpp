#include "Ben_AFK.h"
#include <QHBoxLayout>
#include <QMessageBox>

Ben_AFK::Ben_AFK(QWidget *parent) : QWidget(parent), isConnected(false)
{
    socket = new QTcpSocket(this);

    connectButton = new QPushButton("Connect", this);
    sendButton = new QPushButton("Send", this);
    sendButton->setEnabled(false);
    inputField = new QLineEdit(this);
    outputDisplay = new QTextEdit(this);
    outputDisplay->setReadOnly(true);
    statusLabel = new QLabel("Status: Disconnected", this);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addWidget(statusLabel);
    layout->addWidget(outputDisplay);
    QHBoxLayout *inputLayout = new QHBoxLayout();
    inputLayout->addWidget(inputField);
    inputLayout->addWidget(sendButton);
    layout->addLayout(inputLayout);
    layout->addWidget(connectButton);

    setLayout(layout);
    setWindowTitle("Ouija");

    connect(connectButton, &QPushButton::clicked, this, &Ben_AFK::connectToDaemon);
    connect(sendButton, &QPushButton::clicked, this, &Ben_AFK::sendCommand);
    connect(socket, &QTcpSocket::readyRead, this, &Ben_AFK::readResponse);
    connect(socket, &QTcpSocket::disconnected, this, &Ben_AFK::handleDisconnect);
}

Ben_AFK::~Ben_AFK()
{
    if (socket)
    {
        socket->disconnectFromHost();
        delete socket;
    }
}

void Ben_AFK::connectToDaemon()
{
    if (!isConnected)
    {
        socket->connectToHost("127.0.0.1", 4242);
        if (socket->waitForConnected(3000))
        {
            isConnected = true;
            statusLabel->setText("Status: Connected");
            connectButton->setText("Disconnect");
            sendButton->setEnabled(true);
            outputDisplay->append("Hablando con sus espiritu.");
        }
        else
        {
            QMessageBox::critical(this, "Error", "Failed to connect to Matt_daemon.");
        }
    }
    else
    {
        socket->disconnectFromHost();
    }
}

void Ben_AFK::sendCommand()
{
    if (isConnected && !inputField->text().isEmpty())
    {
        QString command = inputField->text();
        socket->write(command.toUtf8() + '\n');
        inputField->clear();
    }
}

void Ben_AFK::readResponse()
{
    QByteArray response = socket->readAll();
    outputDisplay->append("Daemon: " + QString::fromUtf8(response));
}

void Ben_AFK::handleDisconnect()
{
    isConnected = false;
    statusLabel->setText("Status: Disconnected");
    connectButton->setText("Connect");
    sendButton->setEnabled(false);
    outputDisplay->append("Disconnected from Matt_daemon.");
}
