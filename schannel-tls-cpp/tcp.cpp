
#include "tcp.h"

void tcp_init()
{

}

SOCKET tcp_listen(const std::string& hostname, size_t port)
{
    return 0;
}

SOCKET tcp_accept(SOCKET listen_socket)
{
    return 0;
}

SOCKET tcp_connect(const std::string& hostname, size_t port)
{
    return 0;
}

size_t tcp_send(SOCKET socket, const char* buf, size_t len)
{
    return 0;
}

size_t tcp_recv(SOCKET socket, char* buf, size_t len)
{
    return 0;
}

void tcp_close_socket(SOCKET socket)
{

}
