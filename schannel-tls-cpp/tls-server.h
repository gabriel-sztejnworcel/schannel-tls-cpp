#pragma once

#define SECURITY_WIN32

#include "tls-socket.h"
#include "tls-config.h"
#include "tcp-server.h"

namespace schannel {

class TLSServer
{
public:
    TLSServer(const TLSConfig& tls_config);
    ~TLSServer();

    void listen(const std::string& hostname, short port);
    TLSSocket accept();
    void close();

private:
    TLSConfig tls_config_;
    TCPServer tcp_server_;
    const CERT_CONTEXT* cert_context_;
    CredHandle server_cred_handle_;
};

}; // namespace schannel
