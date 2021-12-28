
#include <WS2tcpip.h>

#include "tcp-client.h"
#include "win32-exception.h"

#include <memory>
#include <functional>

using namespace schannel;

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
        throw Win32Exception(
            "connect", "getaddrinfo", WSAGetLastError()
        );
    }

    // Bind to unique ptr to it will be released at the end
    std::unique_ptr<addrinfo, std::function<void(addrinfo*)>> server_info_uptr(server_info, freeaddrinfo); 
    
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
            throw Win32Exception(
                "connect", "socket", WSAGetLastError()
            );
        }

        int rc = ::connect(win_sock, server_info_current->ai_addr, (int)server_info_current->ai_addrlen);
        if (rc != 0)
        {
            closesocket(win_sock);
            win_sock = INVALID_SOCKET;
            continue;
        }
        
        connected = true;
        break;
    }

    if (!connected)
    {
        throw std::runtime_error("connect: Failed to connect");
    }

    return TCPSocket(win_sock);
}

