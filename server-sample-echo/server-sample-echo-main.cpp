/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#include <tls-server.h>

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>

#include <schannel.h>   // for the protocol version constants

#define SERVER_HOSTNAME "localhost"
#define TLS_SERVER_PORT 8443
#define BUFFER_SIZE 16384

// This function handles a single connection
void client_handler(schannel::TLSSocket tls_socket);

int main()
{
    try
    {
        // Init windows socket library
        schannel::winsock_init();
        
        schannel::TLSConfig tls_config;

        // Only TLS 1.2 or TLS 1.3
        tls_config.enabled_protocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;

        // Get the certificate from the local user personal certificate store
        tls_config.cert_store_location = CERT_SYSTEM_STORE_CURRENT_USER;
        tls_config.cert_store_name = "My";
        tls_config.cert_subject_match = "gabriel-sztejnworcel.com";

        schannel::TLSServer tls_server(tls_config);
        tls_server.listen(SERVER_HOSTNAME, TLS_SERVER_PORT);
        std::cout << "[+] Server is listening on " << SERVER_HOSTNAME << ":" << TLS_SERVER_PORT << std::endl;

        while (true)
        {
            std::cout << "[+] Waiting for client connection..." << std::endl;
            
            // Wait for and accept a client connection
            auto tls_socket = tls_server.accept();
            std::cout << "[+] Client connected" << std::endl;

            // Run the client handler in a separate thread
            std::thread client_handler_thread([tls_socket]()
            {
                client_handler(tls_socket);
            });

            client_handler_thread.detach();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
}

void client_handler(schannel::TLSSocket tls_socket)
{
    while (true)
    {
        // Receive and decrypt
        int bytes = tls_socket.recv();

        // Build a string from the decrypted buffer (stored in the tls socket object)
        std::string msg(tls_socket.decrypted_buffer(), bytes);

        // Reply with the same message
        tls_socket.send(msg.c_str(), (int)msg.length());

        if (msg == "exit")
        {
            break;
        }
    }
}
