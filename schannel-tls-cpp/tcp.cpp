
#pragma comment(lib, "ws2_32")

#include <WS2tcpip.h>

#include "tcp.h"

#define BACKLOG 10

void winsock_init()
{
    WSADATA wsa_data;
    int rc = WSAStartup(MAKEWORD(1, 1), &wsa_data);
    if (rc != 0)
    {
        throw std::runtime_error("WSAStartup: " + std::to_string(WSAGetLastError()));
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
        throw std::runtime_error("send: " + std::to_string(WSAGetLastError()));
    }
    return rc;
}

int TCPSocket::recv(char* buf, int len)
{
    int rc = ::recv(win_sock_, buf, len, 0);
    if (rc == SOCKET_ERROR)
    {
        throw std::runtime_error("recv: " + std::to_string(WSAGetLastError()));
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
    addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    auto port_str = std::to_string(port);
    addrinfo* server_info = nullptr;
    int rc = getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &server_info);
    if (rc != 0)
    {
        throw std::runtime_error("getaddrinfo: " + std::to_string(WSAGetLastError()));
    }

    bool connected = false;
    SOCKET win_sock = INVALID_SOCKET;
    for (
        addrinfo* server_info_current = server_info;
        server_info_current != nullptr;
        server_info_current = server_info_current->ai_next)
    {
        win_sock = socket(
            PF_INET,
            SOCK_STREAM,
            0
        );

        if (win_sock == INVALID_SOCKET)
        {
            throw std::runtime_error("socket: " + std::to_string(WSAGetLastError()));
        }

        int rc = ::connect(win_sock, server_info_current->ai_addr, server_info_current->ai_addrlen);
        if (rc != 0)
        {
            continue;
        }
        
        connected = true;
        break;
    }

    if (!connected)
    {
        throw std::runtime_error("Failed to connect");
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
