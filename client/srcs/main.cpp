#include <QApplication>
#include "Ben_AFK.h"
#include <string>

extern QString ip;
extern int port;

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        ip = "127.0.0.1";
        port = 4242;
    }
    else
    {
        ip = argv[1];
        port = atoi(argv[2]);
    }

    QApplication app(argc, argv);
    Ben_AFK client;
    client.show();
    return app.exec();
}
