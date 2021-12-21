#pragma once

#define SECURITY_WIN32

#include "tcp.h"

#include <Windows.h>
#include <sspi.h>

const CERT_CONTEXT* get_certificate();
CredHandle get_schannel_server_handle(const CERT_CONTEXT* cert_context);
CredHandle get_schannel_client_handle();
SecHandle establish_server_security_context(CredHandle server_cred_handle, SOCKET sock);
SecHandle establish_client_security_context(CredHandle client_cred_handle, const std::string& hostname, SOCKET sock);
