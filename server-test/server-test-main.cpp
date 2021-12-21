
#pragma comment(lib, "schannel-tls-cpp")

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>

#include "tcp.h"

#define SERVER_PORT 8443
#define BUFFER_SIZE 16384

void connection_handler(SOCKET connection_socket);

int main()
{
    try
    {
        tcp_init();

        SOCKET listen_socket = tcp_listen(SERVER_PORT);
        while (true)
        {
            SOCKET connection_socket = tcp_accept(listen_socket);
            std::thread connection_thread([connection_socket]()
            {
                connection_handler(connection_socket);
            });
            connection_thread.detach();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}

void connection_handler(SOCKET connection_socket)
{
    char buf[BUFFER_SIZE] = { 0 };

    while (true)
    {
        memset(buf, 0, BUFFER_SIZE);
        size_t bytes_received = tcp_recv(connection_socket, buf, BUFFER_SIZE - 1);
        std::string str(buf);
        std::cout << "Received: " << str << std::endl;
        
        if (str == "exit")
        {
            break;
        }
    }

    tcp_close_socket(connection_socket);
}
