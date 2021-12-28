/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#define SECURITY_WIN32

#include "tls-socket.h"
#include "tls-config.h"
#include "tcp-server.h"

namespace schannel {

class TLSServer
{
public:
    /**
     * Create a TLS server object.
     * 
     * \param tls_config TLS configuratino for the server
     */
    TLSServer(const TLSConfig& tls_config);

    ~TLSServer();

    /**
     * Start listening for client connections.
     * 
     * \param hostname Server hostname
     * \param port Server port
     */
    void listen(const std::string& hostname, short port);

    /**
     * Wait for and accept a client connection, including the TLS handshake.
     * 
     * \return A TLS socket object for communicating with the client
     */
    TLSSocket accept();

    /**
     * Stop listening.
     * 
     */
    void close();

private:
    TLSConfig tls_config_;
    TCPServer tcp_server_;
    const CERT_CONTEXT* cert_context_;
    CredHandle server_cred_handle_;
};

}; // namespace schannel
