#include <QApplication>
#include "Ben_AFK.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    Ben_AFK client;
    client.show();
    return app.exec();
}
