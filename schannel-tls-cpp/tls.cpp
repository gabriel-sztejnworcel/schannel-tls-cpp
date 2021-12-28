
#include "tls.h"
#include "tcp-client.h"
#include "schannel-helper.h"

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

TLSServer::TLSServer(const TLSConfig& tls_config) :
    tls_config_(tls_config), cert_context_(nullptr), server_cred_handle_({ 0 })
{

}

TLSServer::~TLSServer()
{
    if (cert_context_ != nullptr)
    {
        SchannelHelper::free_cert_context(cert_context_);
        SchannelHelper::free_cred_handle(&server_cred_handle_);
    }
}

void TLSServer::listen(const std::string& hostname, short port)
{
    tcp_server_.listen(hostname, port);
    
    cert_context_ = SchannelHelper::get_certificate(tls_config_.cert_store_location, tls_config_.cert_store_name, tls_config_.cert_subject_match);
    server_cred_handle_ = SchannelHelper::get_schannel_server_handle(cert_context_, tls_config_.enabled_protocols);
}

TLSSocket TLSServer::accept()
{
    auto tcp_socket = tcp_server_.accept();
    SecHandle security_context = SchannelHelper::establish_server_security_context(server_cred_handle_, tcp_socket);
    return TLSSocket(tcp_socket, security_context);
}

void TLSServer::close()
{
    tcp_server_.close();
}

TLSClient::TLSClient(TLSConfig tls_config) :
    tls_config_(tls_config)
{
    client_cred_handle_ = SchannelHelper::get_schannel_client_handle(tls_config_.enabled_protocols);
}

TLSClient::~TLSClient()
{
    SchannelHelper::free_cred_handle(&client_cred_handle_);
}

TLSSocket TLSClient::connect(const std::string& hostname, short port)
{
    auto tcp_socket = tcp_client.connect(hostname, port);
    SecHandle security_context = SchannelHelper::establish_client_security_context(client_cred_handle_, hostname, tcp_socket);
    return TLSSocket(tcp_socket, security_context);
}
