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
    TLSClient(TLSConfig tls_config);
    ~TLSClient();

    TLSSocket connect(const std::string& hostname, short port);

private:
    TLSConfig tls_config_;
    TCPClient tcp_client;
    CredHandle client_cred_handle_;
};

}; // namespace schannel
