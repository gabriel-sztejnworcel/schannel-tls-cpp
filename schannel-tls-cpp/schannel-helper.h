/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#define SECURITY_WIN32

#include <Windows.h>
#include <sspi.h>
#include <schnlsp.h>

#include "tcp-client.h"

#include <memory>

namespace schannel {

class SchannelHelper
{
public:
    static const CERT_CONTEXT* get_certificate(DWORD cert_store_location, const std::string& cert_store_name, const std::string& cert_subject_match);
    static void free_cert_context(const CERT_CONTEXT* cert_context);
    static CredHandle get_schannel_server_handle(const CERT_CONTEXT* cert_context, DWORD enabled_protocols);
    static CredHandle get_schannel_client_handle(DWORD enabled_protocols);
    static void free_cred_handle(CredHandle* cred_handle);

    static SecHandle establish_server_security_context(CredHandle server_cred_handle, TCPSocket tcp_socket);

    static SecHandle establish_client_security_context(
        CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket, bool verify_server_cert
    );

    static SecHandle establish_client_security_context_first_stage(
        CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket
    );

    static SecHandle establish_client_security_context_second_stage(
        SecHandle security_context_handle, CredHandle client_cred_handle,
        const std::string& hostname, TCPSocket tcp_socket, bool verify_server_cert
    );

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

}; // namespace schannel
