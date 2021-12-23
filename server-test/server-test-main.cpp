
#pragma comment(lib, "schannel-tls-cpp")

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>

#include <tcp.h>
#include <tls.h>

#define SERVER_PORT 8443
#define BUFFER_SIZE 16384

//void connection_handler(TLSSocket tls_sock);
//
//int main()
//{
//    try
//    {
//        tcp_init();
//
//        SOCKET listen_sock = tcp_listen(SERVER_PORT);
//        while (true)
//        {
//            SOCKET tcp_sock = tcp_accept(listen_sock);
//            TLSSocket tls_sock = tls_accept(tcp_sock);
//            std::thread connection_thread([tls_sock]()
//            {
//                connection_handler(tls_sock);
//            });
//            connection_thread.detach();
//        }
//    }
//    catch (const std::exception& ex)
//    {
//        std::cerr << "ERROR: " << ex.what() << std::endl;
//    }
//}
//
//void connection_handler(TLSSocket tls_sock)
//{
//    char buf[BUFFER_SIZE] = { 0 };
//
//    while (true)
//    {
//        memset(buf, 0, BUFFER_SIZE);
//        size_t bytes_received = tls_recv(tls_sock, buf, BUFFER_SIZE - 1);
//        std::string str(buf);
//        std::cout << "Received: " << str << std::endl;
//
//        if (str == "exit")
//        {
//            break;
//        }
//    }
//
//    tcp_close_socket(tls_sock.tcp_sock);
//}

//void connection_handler(TCPSocket tcp_socket);
//
//int main()
//{
//    try
//    {
//        winsock_init();
//
//        TCPServer tcp_server;
//        tcp_server.listen(SERVER_PORT);
//
//        while (true)
//        {
//            auto tcp_socket = tcp_server.accept();
//
//            std::thread connection_thread([tcp_socket]()
//            {
//                connection_handler(tcp_socket);
//            });
//
//            connection_thread.detach();
//        }
//    }
//    catch (const std::exception& ex)
//    {
//        std::cerr << "ERROR: " << ex.what() << std::endl;
//    }
//}
//
//void connection_handler(TCPSocket tcp_socket)
//{
//    char buf[BUFFER_SIZE] = { 0 };
//
//    while (true)
//    {
//        memset(buf, 0, BUFFER_SIZE);
//        int bytes_received = tcp_socket.recv(buf, BUFFER_SIZE);
//
//        std::string str(buf, bytes_received);
//        std::cout << "Received: " << str << std::endl;
//
//        if (str == "exit")
//        {
//            break;
//        }
//    }
//
//    tcp_socket.close();
//}

void connection_handler(TLSSocket tls_socket);

int main()
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
                connection_handler(tls_socket);
            });

            connection_thread.detach();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}

void connection_handler(TLSSocket tls_socket)
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
