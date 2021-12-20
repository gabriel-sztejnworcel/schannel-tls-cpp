#pragma once

#include <Windows.h>
#include <winsock.h>

#include <string>

void tcp_init();
SOCKET tcp_listen(const std::string& hostname, size_t port);
SOCKET tcp_accept(SOCKET listen_socket);
SOCKET tcp_connect(const std::string& hostname, size_t port);
size_t tcp_send(SOCKET socket, const char* buf, size_t len);
size_t tcp_recv(SOCKET socket, char* buf, size_t len);
void tcp_close_socket(SOCKET socket);