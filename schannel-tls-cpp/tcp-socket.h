/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#include <Windows.h>
#include <winsock.h>

namespace schannel {

void winsock_init();

class TCPSocket
{
public:
    TCPSocket(SOCKET win_sock);

    int send(const char* buf, int len);
    int recv(char* buf, int len);
    void close();

    // Get underlying socket object for lower level operations
    SOCKET win_sock();

private:
    SOCKET win_sock_;
};

}; // namespace schannel
