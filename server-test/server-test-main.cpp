
#pragma comment(lib, "schannel-tls-cpp")

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>

#include <tcp.h>
#include <tls.h>

#define SERVER_PORT 8443
#define BUFFER_SIZE 16384

void tcp_test();
void tcp_connection_handler(TCPSocket tcp_socket);

void tls_test();
void tls_connection_handler(TLSSocket tls_socket);

int main()
{
    // tcp_test();
    tls_test();
}

void tcp_test()
{
    try
    {
        winsock_init();

        TCPServer tcp_server;
        tcp_server.listen(SERVER_PORT);

        while (true)
        {
            auto tcp_socket = tcp_server.accept();

            std::thread connection_thread([tcp_socket]()
            {
                tcp_connection_handler(tcp_socket);
            });

            connection_thread.detach();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}

void tcp_connection_handler(TCPSocket tcp_socket)
{
    char buf[BUFFER_SIZE] = { 0 };

    while (true)
    {
        memset(buf, 0, BUFFER_SIZE);
        int bytes_received = tcp_socket.recv(buf, BUFFER_SIZE);

        std::string str(buf, bytes_received);
        std::cout << "Received: " << str << std::endl;

        if (str == "exit")
        {
            break;
        }
    }

    tcp_socket.close();
}

void tls_test()
{
    try
    {
        winsock_init();

        TLSConfig tls_config;
        TLSServer tls_server(tls_config);
        tls_server.listen(SERVER_PORT);

        while (true)
        {
            auto tls_socket = tls_server.accept();

            std::thread connection_thread([tls_socket]()
            {
                tls_connection_handler(tls_socket);
            });

            connection_thread.detach();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}

void tls_connection_handler(TLSSocket tls_socket)
{
    char buf[BUFFER_SIZE] = { 0 };

    while (true)
    {
        memset(buf, 0, BUFFER_SIZE);
        int bytes_received = tls_socket.recv(buf, BUFFER_SIZE);

        std::string str(buf, bytes_received);
        std::cout << "Received: " << str << std::endl;

        if (str == "exit")
        {
            break;
        }
    }

    tls_socket.close();
}
