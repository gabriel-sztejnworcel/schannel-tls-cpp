/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#define SECURITY_WIN32

#include <Windows.h>
#include <sspi.h>

#include "tcp-socket.h"

#define TLS_SOCKET_BUFFER_SIZE 16384

namespace schannel {

class TLSSocket
{
public:
    /**
     * Create a TLS socket object.
     * The TLS client/server calls this function after completing the TLS handshake.
     * 
     * \param tcp_socket The underlying TCP socket object
     * \param security_context The established schannel security context
     */
    TLSSocket(TCPSocket tcp_socket, SecHandle security_context);

    /**
     * Send a message to the peer.
     * The message will be encrypted using the established security context.
     * 
     * \param buf The message to send
     * \param len The length of the message
     * \return The number of bytes sent, without the TLS header and trailer
     */
    int send(const char* buf, int len);

    /**
     * Receive data from the peer.
     * The data will be decrypted using the established security context and stored in decrypted_buffer_
     * 
     * \return The number of decrypted bytes
     */
    int recv();

    /**
     * Close the connection
     * 
     */
    void close();

    /**
     * Return the pointer to the decrypted buffer.
     * 
     * \return 
     */
    const char* decrypted_buffer();

    /**
     * Get underlying TCP socket for lower level operations, such as async IO.
     * 
     * \return TCP socket object
     */
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

}; // namespace schannel
