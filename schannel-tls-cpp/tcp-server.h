#pragma once

#include "tcp-socket.h"

#include <string>

class TCPServer
{
public:
    void listen(const std::string& hostname, short port);
    TCPSocket accept();
    void close();

private:
    SOCKET listen_sock_ = INVALID_SOCKET;
};
