
#include <tls-client.h>

#include <iostream>
#include <string>
#include <stdexcept>

#include <schannel.h>   // for the protocol version constants

#define SERVER_HOSTNAME "localhost"
#define TLS_SERVER_PORT 8443
#define BUFFER_SIZE 16384

int main()
{
    try
    {
        // Init windows socket library
        schannel::winsock_init();
        
        schannel::TLSConfig tls_config;

        // Only TLS 1.2 or TLS 1.3
        tls_config.enabled_protocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

        // Skip server certificate verification (should be used only in dev/debug)
        tls_config.verify_server_cert = false;

        schannel::TLSClient tls_client(tls_config);

        // Connect to the server (including the TLS handshake)
        auto tls_socket = tls_client.connect(SERVER_HOSTNAME, TLS_SERVER_PORT);

        while (true)
        {
            // Read a string from the console
            std::cout << "tls-client> ";
            std::string msg;
            std::getline(std::cin, msg);

            // Send to the server
            tls_socket.send(msg.c_str(), (int)msg.length());

            // Receive and decrypt response
            int bytes = tls_socket.recv();

            // Build a string from the decrypted buffer (stored in the tls socket object)
            std::string msg_response(tls_socket.decrypted_buffer(), bytes);

            std::cout << "Request:  " << msg << std::endl;
            std::cout << "Response: " << msg_response << std::endl << std::endl;

            if (msg == "exit")
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
