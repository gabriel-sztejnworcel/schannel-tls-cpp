#pragma once

#include <Windows.h>
#include <winsock.h>

#include <string>

void winsock_init();

class TCPSocket
{
public:
    TCPSocket(SOCKET win_sock);

    int send(const char* buf, int len);
    int recv(char* buf, int len);
    void close();

    // Get underlying socket object for os operations such as async io
    SOCKET win_sock();

private:
    SOCKET win_sock_;
};

class TCPClient
{
public:
    TCPSocket connect(const std::string& hostname, short port);
};

class TCPServer
{
public:
    void listen(short port);
    TCPSocket accept();
    void close();

private:
    SOCKET listen_sock_ = INVALID_SOCKET;
};
