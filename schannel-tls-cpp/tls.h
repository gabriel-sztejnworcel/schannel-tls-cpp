#pragma once

#define SECURITY_WIN32

#include <Windows.h>
#include <sspi.h>

#include <string>

struct TLSSocket
{
    SOCKET tcp_sock;
    SecHandle security_context;
    SecPkgContext_StreamSizes stream_sizes;
};

TLSSocket tls_accept(SOCKET tcp_sock);
TLSSocket tls_connect(const std::string& hostname, short port);
int tls_send(TLSSocket tls_sock, const char* buf, int len);
int tls_recv(TLSSocket tls_sock, char* buf, int len);
void tls_close_socket(TLSSocket tls_sock);
