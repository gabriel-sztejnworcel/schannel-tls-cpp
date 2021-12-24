
#pragma comment(lib, "ws2_32")

#include "tcp.h"

#include <Windows.h>
#include <winsock.h>

#define BACKLOG 10

void winsock_init()
{
    WSADATA wsa_data;
    int rc = WSAStartup(MAKEWORD(1, 1), &wsa_data);
    if (rc != 0)
    {
        throw std::runtime_error("WSAStartup: " + std::to_string(GetLastError()));
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
        throw std::runtime_error("send: " + std::to_string(GetLastError()));
    }
    return rc;
}

int TCPSocket::recv(char* buf, int len)
{
    int rc = ::recv(win_sock_, buf, len, 0);
    if (rc == SOCKET_ERROR)
    {
        throw std::runtime_error("recv: " + std::to_string(GetLastError()));
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

TCPSocket TCPClient::connect(const std::string& hostname, short port)
{
    ULONG address = inet_addr(hostname.c_str());
    if (address == INADDR_NONE)
    {
        hostent* host = gethostbyname(hostname.c_str());
        if (host == nullptr)
        {
            throw std::runtime_error("Could not resolve host name");
        }

        memcpy((char*)&address, host->h_addr_list[0], host->h_length);
    }

    SOCKET win_sock = socket(
        PF_INET,
        SOCK_STREAM,
        0
    );

    if (win_sock == INVALID_SOCKET)
    {
        throw std::runtime_error("socket: " + std::to_string(GetLastError()));
    }

    SOCKADDR_IN sin = { 0 };
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = address;
    sin.sin_port = htons(port);

    int rc = ::connect(win_sock, (sockaddr*)&sin, sizeof(sin));
    if (rc != 0)
    {
        throw std::runtime_error("connect: " + std::to_string(rc));
    }

    return TCPSocket(win_sock);
}

void TCPServer::listen(short port)
{
    SOCKET listen_sock = socket(
        PF_INET,
        SOCK_STREAM,
        0
    );

    if (listen_sock == INVALID_SOCKET)
    {
        throw std::runtime_error("socket: " + std::to_string(GetLastError()));
    }

    SOCKADDR_IN sin = { 0 };
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(port);

    int rc = bind(listen_sock, (SOCKADDR*)&sin, sizeof(sin));
    if (rc == SOCKET_ERROR)
    {
        throw std::runtime_error("bind: " + std::to_string(GetLastError()));
    }

    rc = ::listen(listen_sock, BACKLOG);
    if (rc == SOCKET_ERROR)
    {
        throw std::runtime_error("listen: " + std::to_string(GetLastError()));
    }

    listen_sock_ = listen_sock;
}

TCPSocket TCPServer::accept()
{
    if (listen_sock_ == INVALID_SOCKET)
    {
        throw std::runtime_error("accept was called but the server is not listening");
    }
    
    SOCKET connection_sock = ::accept(listen_sock_, nullptr, nullptr);
    if (connection_sock == INVALID_SOCKET)
    {
        throw std::runtime_error("accept: " + std::to_string(GetLastError()));
    }

    return TCPSocket(connection_sock);
}

void TCPServer::close()
{
    if (listen_sock_ != INVALID_SOCKET)
    {
        closesocket(listen_sock_);
    }
}
