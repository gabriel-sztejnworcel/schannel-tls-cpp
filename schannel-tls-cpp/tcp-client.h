#pragma once

#include "tcp-socket.h"

#include <string>

class TCPClient
{
public:
    TCPSocket connect(const std::string& hostname, short port);
};
