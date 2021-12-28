#pragma once

#define SECURITY_WIN32

#include <Windows.h>
#include <sspi.h>

#include "tcp-socket.h"

#define TLS_SOCKET_BUFFER_SIZE 16384

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
