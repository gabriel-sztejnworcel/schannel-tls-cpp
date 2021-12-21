#pragma once

#include <Windows.h>
#include <winsock.h>

#include <string>

void tcp_init();
SOCKET tcp_listen(short port);
SOCKET tcp_accept(SOCKET listen_sock);
SOCKET tcp_connect(const std::string& hostname, short port);
int tcp_send(SOCKET sock, const char* buf, int len);
int tcp_recv(SOCKET sock, char* buf, int len);
void tcp_close_socket(SOCKET sock);
