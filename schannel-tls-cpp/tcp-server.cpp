
#include <WS2tcpip.h>

#include "tcp-server.h"
#include "win32-exception.h"

#include <memory>
#include <functional>

#define BACKLOG 10

using namespace schannel;

void TCPServer::listen(const std::string& hostname, short port)
{
    addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    auto port_str = std::to_string(port);
    addrinfo* server_info = nullptr;
    int rc = getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &server_info);
    if (rc != 0)
    {
        throw Win32Exception(
            "listen", "getaddrinfo", WSAGetLastError()
        );
    }

    // Bind to unique ptr to it will be released at the end
    std::unique_ptr<addrinfo, std::function<void(addrinfo*)>> server_info_uptr(server_info, freeaddrinfo);

    bool bound = false;
    SOCKET listen_sock = INVALID_SOCKET;
    for (
        addrinfo* server_info_current = server_info;
        server_info_current != nullptr;
        server_info_current = server_info_current->ai_next)
    {
        listen_sock = socket(
            PF_INET,
            SOCK_STREAM,
            0
        );

        if (listen_sock == INVALID_SOCKET)
        {
            throw Win32Exception(
                "listen", "socket", WSAGetLastError()
            );
        }

        int rc = bind(listen_sock, server_info_current->ai_addr, (int)server_info_current->ai_addrlen);
        if (rc == SOCKET_ERROR)
        {
            closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
            continue;
        }

        bound = true;
        break;
    }

    if (!bound)
    {
        throw std::runtime_error("listen: Failed to bind socket");
    }

    rc = ::listen(listen_sock, BACKLOG);
    if (rc == SOCKET_ERROR)
    {
        throw Win32Exception(
            "listen", "listen", WSAGetLastError()
        );
    }

    listen_sock_ = listen_sock;
}

TCPSocket TCPServer::accept()
{
    if (listen_sock_ == INVALID_SOCKET)
    {
        throw std::runtime_error("accept: accept was called but the server is not listening");
    }

    SOCKET connection_sock = ::accept(listen_sock_, nullptr, nullptr);
    if (connection_sock == INVALID_SOCKET)
    {
        throw Win32Exception(
            "accept", "accept", WSAGetLastError()
        );
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
