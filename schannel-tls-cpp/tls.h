#pragma once

#define SECURITY_WIN32

#include "tcp.h"

#include <Windows.h>
#include <sspi.h>

#include <string>

struct TLSConfig
{

};

class TLSSocket
{
public:
    TLSSocket(TCPSocket tcp_socket, SecHandle security_context);

    int send(const char* buf, int len);
    int recv(char* buf, int len);
    void close();

    // Get underlying tcp socket for lower level operations
    TCPSocket scp_socket();

private:
    TCPSocket tcp_socket_;
    SecHandle security_context_;
    SecPkgContext_StreamSizes stream_sizes_;
};

class TLSServer
{
public:
    TLSServer(TLSConfig tls_config);

    void listen(short port);
    TLSSocket accept();

private:
    TLSConfig tls_config_;
    TCPServer tcp_server_;
};

class TLSClient
{
public:
    TLSClient(TLSConfig tls_config);
    TLSSocket connect(const std::string& hostname, short port);

private:
    TLSConfig tls_config_;
    TCPClient tcp_client;
};
