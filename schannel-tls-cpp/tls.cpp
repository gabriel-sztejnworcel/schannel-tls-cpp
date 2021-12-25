
#include "tls.h"
#include "tcp.h"
#include "schannel-helper.h"

TLSSocket::TLSSocket(TCPSocket tcp_socket, SecHandle security_context) :
    tcp_socket_(tcp_socket), security_context_(security_context)
{
    stream_sizes_ = SchannelHelper::get_stream_sizes(security_context_);
}

int TLSSocket::send(const char* buf, int len)
{
    int out_len = len + stream_sizes_.cbHeader + stream_sizes_.cbTrailer;
    auto out_buf = std::make_unique<char[]>(out_len);

    int out_len_result = SchannelHelper::encrypt_message(
        security_context_, stream_sizes_, buf, len, out_buf.get(), out_len
    );

    int bytes_sent = tcp_socket_.send(out_buf.get(), out_len_result);
    return bytes_sent - stream_sizes_.cbHeader - stream_sizes_.cbTrailer;
}

int TLSSocket::recv(char* buf, int len)
{
    int recv_len = len + stream_sizes_.cbHeader + stream_sizes_.cbTrailer;
    auto recv_buf = std::make_unique<char[]>(recv_len);
    int bytes_received = tcp_socket_.recv(recv_buf.get(), recv_len);

    int decrypted_len = SchannelHelper::decrypt_message(
        security_context_, stream_sizes_, recv_buf.get(), recv_len, buf, len
    );

    return decrypted_len;
}

void TLSSocket::close()
{
    tcp_socket_.close();
    SchannelHelper::delete_security_context(&security_context_);
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
