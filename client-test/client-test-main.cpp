
#pragma comment(lib, "schannel-tls-cpp")

#include <iostream>
#include <string>
#include <stdexcept>

#include <tcp.h>
#include <tls.h>

#define SERVER_HOSTNAME "localhost"
#define SERVER_PORT 8443

//int main()
//{
//    try
//    {
//        tcp_init();
//
//        TLSSocket tls_sock = tls_connect(SERVER_HOSTNAME, SERVER_PORT);
//        while (true)
//        {
//            std::string str;
//            std::getline(std::cin, str);
//
//            tls_send(tls_sock, str.c_str(), (int)str.length());
//
//            if (str == "exit")
//            {
//                break;
//            }
//        }
//    }
//    catch (const std::exception& ex)
//    {
//        std::cerr << "ERROR: " << ex.what() << std::endl;
//    }
//}

//int main()
//{
//    try
//    {
//        winsock_init();
//
//        TCPClient tcp_client;
//        auto tcp_socket = tcp_client.connect(SERVER_HOSTNAME, SERVER_PORT);
//
//        while (true)
//        {
//            std::string str;
//            std::getline(std::cin, str);
//
//            tcp_socket.send(str.c_str(), (int)str.length());
//
//            if (str == "exit")
//            {
//                break;
//            }
//        }
//    }
//    catch (const std::exception& ex)
//    {
//        std::cerr << "ERROR: " << ex.what() << std::endl;
//    }
//}

int main()
{
    try
    {
        winsock_init();

        TLSConfig tls_config;
        TLSClient tls_client(tls_config);
        auto tls_socket = tls_client.connect(SERVER_HOSTNAME, SERVER_PORT);

        while (true)
        {
            std::string str;
            std::getline(std::cin, str);

            tls_socket.send(str.c_str(), (int)str.length());

            if (str == "exit")
            {
                break;
            }
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}
