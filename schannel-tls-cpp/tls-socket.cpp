/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#include "tls-socket.h"
#include "schannel-helper.h"

using namespace schannel;

TLSSocket::TLSSocket(TCPSocket tcp_socket, SecHandle security_context) :
    tcp_socket_(tcp_socket), security_context_(security_context)
{
    stream_sizes_ = SchannelHelper::get_stream_sizes(security_context_);
}

int TLSSocket::send(const char* buf, int len)
{
    int out_len_result = SchannelHelper::encrypt_message(
        security_context_, stream_sizes_, buf, len, encrypted_buffer_, TLS_SOCKET_BUFFER_SIZE
    );

    int bytes_sent = tcp_socket_.send(encrypted_buffer_, out_len_result);
    return bytes_sent - stream_sizes_.cbHeader - stream_sizes_.cbTrailer;
}

int TLSSocket::recv()
{
    int total_decrypted_len = 0;

    // We might have leftovers, an incomplete message from a previous call.
    // Calculate the available buffer length for tcp recv.
    int recv_max_len = TLS_SOCKET_BUFFER_SIZE - buffer_to_decrypt_offset_;
    int bytes_received = tcp_socket_.recv(buffer_to_decrypt_ + buffer_to_decrypt_offset_, recv_max_len);

    int decrypted_buffer_offset = 0;
    int encrypted_buffer_len = buffer_to_decrypt_offset_ + bytes_received;
    buffer_to_decrypt_offset_ = 0;
    while (true)
    {
        if (buffer_to_decrypt_offset_ >= encrypted_buffer_len)
        {
            // Reached the encrypted buffer length, we decrypted everything so we can stop.
            break;
        }

        int decrypted_len = SchannelHelper::decrypt_message(
            security_context_,
            stream_sizes_,
            buffer_to_decrypt_ + buffer_to_decrypt_offset_,
            encrypted_buffer_len - buffer_to_decrypt_offset_,
            decrypted_buffer_ + decrypted_buffer_offset,
            TLS_SOCKET_BUFFER_SIZE + TLS_SOCKET_BUFFER_SIZE - decrypted_buffer_offset
        );

        if (decrypted_len == -1)
        {
            // Incomplete message, we shuold keep it so it will be decrypted on the next call to recv().
            // Shift the remaining buffer to the beginning and break the loop.

            memcpy(
                buffer_to_decrypt_,
                buffer_to_decrypt_ + buffer_to_decrypt_offset_,
                encrypted_buffer_len - buffer_to_decrypt_offset_
            );

            break;
        }

        total_decrypted_len += decrypted_len;
        decrypted_buffer_offset += decrypted_len;
        buffer_to_decrypt_offset_ += stream_sizes_.cbHeader + decrypted_len + stream_sizes_.cbTrailer;
    }

    buffer_to_decrypt_offset_ = encrypted_buffer_len - buffer_to_decrypt_offset_;
    return total_decrypted_len;
}

void TLSSocket::close()
{
    tcp_socket_.close();
    SchannelHelper::delete_security_context(&security_context_);
}

const char* TLSSocket::decrypted_buffer()
{
    return decrypted_buffer_;
}

TCPSocket TLSSocket::tcp_socket()
{
    return tcp_socket_;
}
