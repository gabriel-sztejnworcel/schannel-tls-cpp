/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#define SECURITY_WIN32

#include <Windows.h>
#include <sspi.h>

#include "tcp-client.h"
#include "tls-config.h"
#include "tls-socket.h"

#include <string>

namespace schannel {

class TLSClient
{
public:
    /**
     * Create a TLS client object.
     * 
     * \param tls_config TLS configuration for connecting to servers
     */
    TLSClient(TLSConfig tls_config);

    ~TLSClient();

    /**
     * Establish a TLS connection to a TLS server.
     * 
     * \param hostname The server hostname
     * \param port The server port
     * \return A TLS socket object for communicating with the server
     */
    TLSSocket connect(const std::string& hostname, short port);

private:
    TLSConfig tls_config_;
    TCPClient tcp_client;
    CredHandle client_cred_handle_;
};

}; // namespace schannel
