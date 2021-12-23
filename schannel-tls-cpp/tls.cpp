
#include "tls.h"
#include "tcp.h"
#include "schannel.h"

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
}

TCPSocket TLSSocket::scp_socket()
{
    return tcp_socket_;
}

TLSServer::TLSServer(TLSConfig tls_config) :
    tls_config_(tls_config)
{

}

void TLSServer::listen(short port)
{
    tcp_server_.listen(port);
}

TLSSocket TLSServer::accept()
{
    // TODO: handle exceptions
    auto tcp_socket = tcp_server_.accept();
    const CERT_CONTEXT* cert_context = SchannelHelper::get_certificate();
    CredHandle server_cred_handle = SchannelHelper::get_schannel_server_handle(cert_context);
    SecHandle security_context = SchannelHelper::establish_server_security_context(server_cred_handle, tcp_socket);
    return TLSSocket(tcp_socket, security_context);
}

TLSClient::TLSClient(TLSConfig tls_config) :
    tls_config_(tls_config)
{

}

TLSSocket TLSClient::connect(const std::string& hostname, short port)
{
    auto tcp_socket = tcp_client.connect(hostname, port);
    CredHandle client_cred_handle = SchannelHelper::get_schannel_client_handle();
    SecHandle security_context = SchannelHelper::establish_client_security_context(client_cred_handle, hostname, tcp_socket);
    return TLSSocket(tcp_socket, security_context);
}
