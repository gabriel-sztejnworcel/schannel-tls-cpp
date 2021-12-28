
#pragma comment(lib, "ws2_32")

#include "tcp-socket.h"
#include "win32-exception.h"

using namespace schannel;

void winsock_init()
{
    WSADATA wsa_data;
    int rc = WSAStartup(MAKEWORD(1, 1), &wsa_data);
    if (rc != 0)
    {
        throw Win32Exception(
            "winsock_init", "WSAStartup", WSAGetLastError()
        );
    }
}

TCPSocket::TCPSocket(SOCKET win_sock) : win_sock_(win_sock)
{

}

int TCPSocket::send(const char* buf, int len)
{
    int rc = ::send(win_sock_, buf, len, 0);
    if (rc == SOCKET_ERROR)
    {
        throw Win32Exception(
            "send", "send", WSAGetLastError()
        );
    }
    return rc;
}

int TCPSocket::recv(char* buf, int len)
{
    int rc = ::recv(win_sock_, buf, len, 0);
    if (rc == SOCKET_ERROR)
    {
        throw Win32Exception(
            "recv", "recv", WSAGetLastError()
        );
    }
    return rc;
}

void TCPSocket::close()
{
    ::closesocket(win_sock_);
}

SOCKET TCPSocket::win_sock()
{
    return win_sock_;
}
