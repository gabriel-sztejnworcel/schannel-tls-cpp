#pragma once

#define SECURITY_WIN32

#include "tcp.h"

#include <Windows.h>
#include <sspi.h>

#include <string>

#define TLS_SOCKET_BUFFER_SIZE 16384

struct TLSConfig
{
    DWORD enabled_protocols = 0;
    DWORD cert_store_location = 0;
    std::string cert_store_name;
    std::string cert_subject_match;
};

class TLSSocket
{
public:
    TLSSocket(TCPSocket tcp_socket, SecHandle security_context);

    int send(const char* buf, int len);
    int recv();
    void close();

    const char* decrypted_buffer();

    // Get underlying tcp socket for lower level operations
    TCPSocket tcp_socket();

private:
    TCPSocket tcp_socket_;
    SecHandle security_context_;
    SecPkgContext_StreamSizes stream_sizes_;

    char encrypted_buffer_[TLS_SOCKET_BUFFER_SIZE] = { 0 };
    char buffer_to_decrypt_[TLS_SOCKET_BUFFER_SIZE] = { 0 };
    char decrypted_buffer_[TLS_SOCKET_BUFFER_SIZE + TLS_SOCKET_BUFFER_SIZE] = { 0 };
    int buffer_to_decrypt_offset_ = 0;
};

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
