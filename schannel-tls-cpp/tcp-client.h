/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#include "tcp-socket.h"

#include <string>

namespace schannel {

class TCPClient
{
public:
    TCPSocket connect(const std::string& hostname, short port);
};

}; // namespace schannel
