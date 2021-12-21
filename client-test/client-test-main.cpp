
#pragma comment(lib, "schannel-tls-cpp")

#include <iostream>
#include <string>
#include <stdexcept>

#include <tcp.h>

#define SERVER_HOSTNAME "localhost"
#define SERVER_PORT 8443

int main()
{
    try
    {
        tcp_init();

        SOCKET sock = tcp_connect(SERVER_HOSTNAME, SERVER_PORT);
        while (true)
        {
            std::string str;
            std::getline(std::cin, str);

            tcp_send(sock, str.c_str(), (int)str.length());

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
