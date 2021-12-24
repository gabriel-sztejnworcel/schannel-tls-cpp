#pragma once

#define SECURITY_WIN32

#include "tcp.h"

#include <Windows.h>
#include <sspi.h>

#include <memory>

class SchannelHelper
{
public:
    static const CERT_CONTEXT* get_certificate();
    static void free_cert_context(const CERT_CONTEXT* cert_context);
    static CredHandle get_schannel_server_handle(const CERT_CONTEXT* cert_context);
    static CredHandle get_schannel_client_handle();
    static void free_cred_handle(CredHandle* cred_handle);

    static SecHandle establish_server_security_context(CredHandle server_cred_handle, TCPSocket tcp_socket);
    static SecHandle establish_client_security_context(CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket);
    static void delete_security_context(SecHandle* security_context);

    static SecPkgContext_StreamSizes get_stream_sizes(SecHandle security_context);

    static int encrypt_message(
        SecHandle security_context, SecPkgContext_StreamSizes stream_sizes,
        const char* in_buf, int in_len,
        char* out_buf, int out_len
    );

    static int decrypt_message(
        SecHandle security_context, SecPkgContext_StreamSizes stream_sizes,
        const char* in_buf, int in_len,
        char* out_buf, int out_len
    );
};
