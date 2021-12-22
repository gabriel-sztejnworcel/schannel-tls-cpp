
#include "tls.h"
#include "tcp.h"
#include "schannel.h"

TLSSocket tls_accept(SOCKET tcp_sock)
{
    TLSSocket tls_sock;
    tls_sock.tcp_sock = tcp_sock;
    const CERT_CONTEXT* cert_context = get_certificate();
    CredHandle server_cred_handle = get_schannel_server_handle(cert_context);
    tls_sock.security_context = establish_server_security_context(server_cred_handle, tcp_sock);
    tls_sock.stream_sizes = get_stream_sizes(tls_sock.security_context);
    return tls_sock;
}

TLSSocket tls_connect(const std::string& hostname, short port)
{
    TLSSocket tls_sock;
    tls_sock.tcp_sock = tcp_connect(hostname, port);
    CredHandle client_cred_handle = get_schannel_client_handle();
    tls_sock.security_context = establish_client_security_context(client_cred_handle, hostname, tls_sock.tcp_sock);
    tls_sock.stream_sizes = get_stream_sizes(tls_sock.security_context);
    return tls_sock;
}

int tls_send(TLSSocket tls_sock, const char* buf, int len)
{
    auto encrypted_buffer = encrypt_message(buf, len, tls_sock.stream_sizes, tls_sock.security_context);
    return tcp_send(tls_sock.tcp_sock, encrypted_buffer.data.get(), (int)encrypted_buffer.size);
}

int tls_recv(TLSSocket tls_sock, char* buf, int len)
{
    auto read_buf_len = len + tls_sock.stream_sizes.cbHeader + tls_sock.stream_sizes.cbTrailer;
    auto read_buf = std::make_unique<char[]>(read_buf_len);
    int bytes_received = tcp_recv(tls_sock.tcp_sock, read_buf.get(), read_buf_len);
    auto decrypted_buffer = decrypt_message(read_buf.get(), bytes_received, tls_sock.stream_sizes, tls_sock.security_context);

    if (decrypted_buffer.size > len)
    {
        throw std::runtime_error("Unexpected decrypted message length");
    }

    memcpy(buf, decrypted_buffer.data.get(), decrypted_buffer.size);

    return (int)decrypted_buffer.size;
}

void tls_close_socket(TLSSocket tls_sock)
{
    tcp_close_socket(tls_sock.tcp_sock);
}
