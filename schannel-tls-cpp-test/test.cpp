
#include "pch.h"

#include <tcp.h>
#include <tls.h>

#include <thread>
#include <mutex>

#include <schannel.h>

#define SERVER_HOSTNAME "localhost"
#define TCP_SERVER_PORT 8080
#define TLS_SERVER_PORT 8443
#define BUFFER_SIZE 16384

void output_debug(const std::string& msg)
{
    static std::mutex console_mtx;
    std::cout << msg << std::endl;
}

TEST(tcp_tests, test_simple_tcp_client_server)
{
    winsock_init();
    
    std::string msg_received;

    std::thread server_thread([&msg_received]()
    {
        try
        {
            TCPServer tcp_server;
            tcp_server.listen(SERVER_HOSTNAME, TCP_SERVER_PORT);

            auto tcp_socket = tcp_server.accept();
            char buf[BUFFER_SIZE] = { 0 };

            int bytes_received = tcp_socket.recv(buf, BUFFER_SIZE);
            msg_received = std::string(buf, bytes_received);

            tcp_socket.close();
            tcp_server.close();

        }
        catch (const std::exception& ex)
        {
            output_debug(std::string("ERROR: ") + ex.what());
        }
    });

    std::thread client_thread([]()
    {
        try
        {
            TCPClient tcp_client;
            auto tcp_socket = tcp_client.connect(SERVER_HOSTNAME, TCP_SERVER_PORT);

            std::string msg_to_send = "Hello World";
            tcp_socket.send(msg_to_send.c_str(), (int)msg_to_send.length());

            tcp_socket.close();
        }
        catch (const std::exception& ex)
        {
            output_debug(std::string("ERROR: ") + ex.what());
        }
    });

    client_thread.join();
    server_thread.join();

    EXPECT_EQ(msg_received, "Hello World");
}

TEST(tls_tests, test_simple_tls_client_server)
{
    winsock_init();

    std::string msg_received;

    std::thread server_thread([&msg_received]()
    {
        try
        {
            TLSConfig tls_config;
            tls_config.enabled_protocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
            tls_config.cert_store_location = CERT_SYSTEM_STORE_CURRENT_USER;
            tls_config.cert_store_name = "My";
            tls_config.cert_subject_match = "gabriel-sztejnworcel.com";

            TLSServer tls_server(tls_config);
            tls_server.listen(SERVER_HOSTNAME, TLS_SERVER_PORT);

            auto tls_socket = tls_server.accept();
            char buf[BUFFER_SIZE] = { 0 };

            int bytes_received = tls_socket.recv(buf, BUFFER_SIZE);
            msg_received = std::string(buf, bytes_received);

            tls_socket.close();
            tls_server.close();
        }
        catch (const std::exception& ex)
        {
            output_debug(std::string("ERROR: ") + ex.what());
        }
    });

    std::thread client_thread([]()
    {
        try
        {
            TLSConfig tls_config;
            tls_config.enabled_protocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

            TLSClient tls_client(tls_config);
            auto tls_socket = tls_client.connect(SERVER_HOSTNAME, TLS_SERVER_PORT);

            std::string msg_to_send = "Hello World";
            tls_socket.send(msg_to_send.c_str(), (int)msg_to_send.length());

            tls_socket.close();
        }
        catch (const std::exception& ex)
        {
            output_debug(std::string("ERROR: ") + ex.what());
        }
    });

    client_thread.join();
    server_thread.join();

    EXPECT_EQ(msg_received, "Hello World");
}
