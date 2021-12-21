
#include "tls.h"
#include "tcp.h"
#include "schannel.h"

TLSSocket tls_accept(SOCKET tcp_sock)
{
    TLSSocket tls_socket;
    tls_socket.tcp_sock = tcp_sock;
    const CERT_CONTEXT* cert_context = get_certificate();
    CredHandle server_cred_handle = get_schannel_server_handle(cert_context);
    tls_socket.security_context = establish_server_security_context(server_cred_handle, tcp_sock);
    return tls_socket;
}

TLSSocket tls_connect(const std::string& hostname, short port)
{
    TLSSocket tls_sock;
    tls_sock.tcp_sock = tcp_connect(hostname, port);
    CredHandle client_cred_handle = get_schannel_client_handle();
    tls_sock.security_context = establish_client_security_context(client_cred_handle, hostname, tls_sock.sock);
    return tls_sock;
}

int tls_send(TLSSocket tls_sock, const char* buf, int len)
{

}

int tls_recv(TLSSocket tls_sock, char* buf, int len)
{

}

void tls_close_socket(TLSSocket tls_sock)
{
    tcp_close_socket(tls_sock.tcp_sock);
}
