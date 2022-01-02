/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma comment(lib, "Secur32")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "ws2_32")

#include "schannel-helper.h"
#include "win32-exception.h"
#include "defer-function.h"

#include <sstream>
#include <memory>
#include <iostream>

#define SCHANNEL_NEGOTIATE_BUFFER_SIZE 16384

using namespace schannel;

static void init_sec_buffer(SecBuffer& secure_buffer, unsigned long type, unsigned long len, void* buffer)
{
    secure_buffer.BufferType = type;
    secure_buffer.cbBuffer = len;
    secure_buffer.pvBuffer = buffer;
}

static void init_sec_buffer_desc(
    SecBufferDesc& secure_buffer_desc, unsigned long version, unsigned long num_buffers, SecBuffer* buffers)
{
    secure_buffer_desc.ulVersion = version;
    secure_buffer_desc.cBuffers = num_buffers;
    secure_buffer_desc.pBuffers = buffers;
}

static void send_and_verify_all_sent(TCPSocket& tcp_socket, const char* buf, int len)
{
    int sent = tcp_socket.send(buf, len);
    if (sent != len)
    {
        throw std::runtime_error(
            "send_and_verify_all_sent: Unexpected number of bytes sent to server"
        );
    }
}

static void free_all_buffers(SecBufferDesc& secure_buffer_desc)
{
    for (unsigned long i = 0; i < secure_buffer_desc.cBuffers; ++i)
    {
        auto buffer = secure_buffer_desc.pBuffers[i].pvBuffer;
        if (buffer != nullptr)
        {
            FreeContextBuffer(buffer);
        }
    }
}

const CERT_CONTEXT* SchannelHelper::get_certificate(
    DWORD cert_store_location, const std::string& cert_store_name, const std::string& cert_subject_match)
{
    std::wstring cert_store_name_wstr(cert_store_name.begin(), cert_store_name.end());
        
    HCERTSTORE personal_cert_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        cert_store_location,
        cert_store_name_wstr.c_str()
    );

    if (personal_cert_store == nullptr)
    {
        throw Win32Exception(
            "get_certificate", "CertOpenStore", GetLastError()
        );
    }

    DeferFunction cert_close_store_deferred([personal_cert_store]() { CertCloseStore(personal_cert_store, 0); });

    std::wstring cert_subject_wstr(
        cert_subject_match.begin(), cert_subject_match.end()
    );

    const CERT_CONTEXT* cert_context = CertFindCertificateInStore(
        personal_cert_store,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        cert_subject_wstr.c_str(),
        nullptr
    );

    if (cert_context == nullptr)
    {
        throw Win32Exception(
            "get_certificate", "CertFindCertificateInStore", GetLastError()
        );
    }

    return cert_context;
}

void SchannelHelper::free_cert_context(const CERT_CONTEXT* cert_context)
{
    CertFreeCertificateContext(cert_context);
}

CredHandle SchannelHelper::get_schannel_server_handle(const CERT_CONTEXT* cert_context, DWORD enabled_protocols)
{
    SCHANNEL_CRED cred_data = { 0 };
    cred_data.dwVersion = SCHANNEL_CRED_VERSION;
    cred_data.grbitEnabledProtocols = enabled_protocols;
    cred_data.paCred = &cert_context;
    cred_data.cCreds = 1;

    CredHandle cred_handle;
    TimeStamp life_time;
    wchar_t unisp_name[] = UNISP_NAME;

    SECURITY_STATUS sec_status = AcquireCredentialsHandle(nullptr, unisp_name, SECPKG_CRED_INBOUND, nullptr,
                                                          &cred_data, nullptr, nullptr, &cred_handle, &life_time);

    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "get_schannel_server_handle", "AcquireCredentialsHandle", sec_status
        );
    }

    return cred_handle;
}

CredHandle SchannelHelper::get_schannel_client_handle(DWORD enabled_protocols)
{
    SCHANNEL_CRED cred_data = { 0 };
    cred_data.dwVersion = SCHANNEL_CRED_VERSION;
    cred_data.grbitEnabledProtocols = enabled_protocols;

    CredHandle cred_handle;
    TimeStamp life_time;
    wchar_t unisp_name[] = UNISP_NAME;

    SECURITY_STATUS sec_status = AcquireCredentialsHandle(nullptr, unisp_name, SECPKG_CRED_OUTBOUND,
                                                          nullptr, &cred_data, nullptr, nullptr,
                                                          &cred_handle, &life_time);

    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "get_schannel_client_handle", "AcquireCredentialsHandle", sec_status
        );
    }

    return cred_handle;
}

void SchannelHelper::free_cred_handle(CredHandle* cred_handle)
{
    SECURITY_STATUS sec_status = FreeCredentialsHandle(cred_handle);
    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "free_cred_handle", "FreeCredentialsHandle", sec_status
        );
    }
}

SecHandle SchannelHelper::establish_server_security_context(CredHandle server_cred_handle, TCPSocket tcp_socket)
{
    SecHandle security_context_handle = { 0 };

    try
    {
        // Input buffer
        auto buffer_in = std::make_unique<char[]>(SCHANNEL_NEGOTIATE_BUFFER_SIZE);
        
        SecBuffer secure_buffer_in[2] = { 0 };
        init_sec_buffer(secure_buffer_in[0], SECBUFFER_TOKEN, SCHANNEL_NEGOTIATE_BUFFER_SIZE, buffer_in.get());
        init_sec_buffer(secure_buffer_in[1], SECBUFFER_EMPTY, 0, nullptr);
        
        SecBufferDesc secure_buffer_desc_in = { 0 };
        init_sec_buffer_desc(secure_buffer_desc_in, SECBUFFER_VERSION, 2, secure_buffer_in);

        // Output buffer
        SecBuffer secure_buffer_out[3] = { 0 };
        init_sec_buffer(secure_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
        init_sec_buffer(secure_buffer_out[1], SECBUFFER_ALERT, 0, nullptr);
        init_sec_buffer(secure_buffer_out[2], SECBUFFER_EMPTY, 0, nullptr);
        
        SecBufferDesc secure_buffer_desc_out = { 0 };
        init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 3, secure_buffer_out);

        unsigned long context_requirements = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY;

        // We use ASC_REQ_ALLOCATE_MEMORY which means the buffers will be allocated for us, we need to make sure we free them.
        DeferFunction free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

        ULONG context_attributes = 0;
        TimeStamp life_time = { 0 };

        bool authn_completed = false;
        bool first_iteration = true;
        while (!authn_completed)
        {
            secure_buffer_in[0].cbBuffer = tcp_socket.recv((char*)secure_buffer_in[0].pvBuffer, SCHANNEL_NEGOTIATE_BUFFER_SIZE);

            SECURITY_STATUS sec_status = AcceptSecurityContext(&server_cred_handle,
                                                               first_iteration ? nullptr : &security_context_handle,
                                                               &secure_buffer_desc_in, context_requirements, 0,
                                                               &security_context_handle, &secure_buffer_desc_out,
                                                               &context_attributes, &life_time);

            first_iteration = false;

            switch (sec_status)
            {
            case SEC_E_OK:
            case SEC_I_CONTINUE_NEEDED:
                
                if (secure_buffer_out[0].cbBuffer > 0)
                {
                    send_and_verify_all_sent(tcp_socket, (const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
                }

                if (sec_status == SEC_E_OK)
                {
                    authn_completed = true;
                }

                break;
                break;

            case SEC_I_COMPLETE_AND_CONTINUE:
            case SEC_I_COMPLETE_NEEDED:
            {
                SECURITY_STATUS complete_sec_status = SEC_E_OK; 
                complete_sec_status = CompleteAuthToken(&security_context_handle, &secure_buffer_desc_out);

                if (complete_sec_status != SEC_E_OK)
                {
                    throw Win32Exception(
                        "establish_server_security_context", "CompleteAuthToken", complete_sec_status
                    );
                }

                if (secure_buffer_out[0].cbBuffer > 0)
                {
                    send_and_verify_all_sent(tcp_socket, (const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
                }

                if (sec_status == SEC_I_COMPLETE_NEEDED)
                {
                    authn_completed = true;
                }

                break;
            }

            default:
                throw Win32Exception(
                    "establish_server_security_context", "AcceptSecurityContext", sec_status
                );
            }
        }
    }
    catch (...)
    {
        SchannelHelper::delete_security_context(&security_context_handle);
        throw;
    }

    return security_context_handle;
}

SecHandle SchannelHelper::establish_client_security_context(
    CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket, bool verify_server_cert)
{
    SecHandle security_context_handle = SchannelHelper::establish_client_security_context_first_stage(
        client_cred_handle, hostname, tcp_socket
    );

    security_context_handle = SchannelHelper::establish_client_security_context_second_stage(
        security_context_handle, client_cred_handle, hostname, tcp_socket, verify_server_cert
    );

    return security_context_handle;
}

SecHandle SchannelHelper::establish_client_security_context_first_stage(
    CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket)
{
    SecHandle security_context_handle = { 0 };
    
    try
    {
        SecBuffer secure_buffer_out[1] = { 0 };
        init_sec_buffer(secure_buffer_out[0], SECBUFFER_EMPTY, 0, nullptr);

        SecBufferDesc secure_buffer_desc_out = { 0 };
        init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 1, secure_buffer_out);

        ULONG context_attributes = 0;
        TimeStamp life_time = { 0 };

        std::wstring hostname_wstr(hostname.begin(), hostname.end());

        unsigned long context_requirements = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY;

        // We use ISC_REQ_ALLOCATE_MEMORY which means the buffers will be allocated for us, we need to make sure we free them.
        DeferFunction free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

        SECURITY_STATUS sec_status = InitializeSecurityContext(&client_cred_handle, nullptr, (wchar_t*)hostname_wstr.c_str(),
                                                               context_requirements, 0, 0, nullptr, 0, &security_context_handle,
                                                               &secure_buffer_desc_out, &context_attributes, &life_time);

        if (sec_status != SEC_I_CONTINUE_NEEDED)
        {
            throw Win32Exception(
                "establish_client_security_context", "InitializeSecurityContext", sec_status
            );
        }

        if (secure_buffer_out[0].cbBuffer > 0)
        {
            send_and_verify_all_sent(tcp_socket, (const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
        }
    }
    catch (...)
    {
        SchannelHelper::delete_security_context(&security_context_handle);
        throw;
    }

    return security_context_handle;
}

SecHandle SchannelHelper::establish_client_security_context_second_stage(
    SecHandle security_context_handle, CredHandle client_cred_handle, const std::string& hostname,
    TCPSocket tcp_socket, bool verify_server_cert)
{
    try
    {
        // Input buffer
        auto buffer_in = std::make_unique<char[]>(SCHANNEL_NEGOTIATE_BUFFER_SIZE);
        SecBuffer secure_buffer_in[4] = { 0 };
        init_sec_buffer(secure_buffer_in[0], SECBUFFER_TOKEN, SCHANNEL_NEGOTIATE_BUFFER_SIZE, buffer_in.get());
        init_sec_buffer(secure_buffer_in[1], SECBUFFER_EMPTY, 0, nullptr);
        init_sec_buffer(secure_buffer_in[2], SECBUFFER_EMPTY, 0, nullptr);
        init_sec_buffer(secure_buffer_in[3], SECBUFFER_EMPTY, 0, nullptr);

        SecBufferDesc secure_buffer_desc_in = { 0 };
        init_sec_buffer_desc(secure_buffer_desc_in, SECBUFFER_VERSION, 4, secure_buffer_in);

        // Output buffer
        SecBuffer secure_buffer_out[3] = { 0 };
        init_sec_buffer(secure_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
        init_sec_buffer(secure_buffer_out[1], SECBUFFER_ALERT, 0, nullptr);
        init_sec_buffer(secure_buffer_out[2], SECBUFFER_EMPTY, 0, nullptr);

        SecBufferDesc secure_buffer_desc_out = { 0 };
        init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 3, secure_buffer_out);

        ULONG context_attributes = 0;
        TimeStamp life_time = { 0 };

        std::wstring hostname_wstr(hostname.begin(), hostname.end());

        unsigned long context_requirements = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY;

        // We use ISC_REQ_ALLOCATE_MEMORY which means the buffers will be allocated for us, we need to make sure we free them.
        DeferFunction free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

        if (!verify_server_cert)
        {
            context_requirements |= ISC_REQ_MANUAL_CRED_VALIDATION;
        }

        bool authn_completed = false;
        int recv_offset = 0;
        while (!authn_completed)
        {
            std::cout << "recv_offset: " << recv_offset << std::endl;

            secure_buffer_in[0].cbBuffer = recv_offset + tcp_socket.recv(
                (char*)secure_buffer_in[0].pvBuffer + recv_offset, SCHANNEL_NEGOTIATE_BUFFER_SIZE
            );

            std::cout << "secure_buffer_in[0].cbBuffer: " << secure_buffer_in[0].cbBuffer << std::endl;

            recv_offset = 0;

            SECURITY_STATUS sec_status = InitializeSecurityContext(&client_cred_handle, &security_context_handle,
                                                                   (wchar_t*)hostname_wstr.c_str(), context_requirements, 0, 0,
                                                                   &secure_buffer_desc_in, 0, &security_context_handle,
                                                                   &secure_buffer_desc_out, &context_attributes, &life_time);

            switch (sec_status)
            {
            case SEC_E_OK:
            case SEC_I_CONTINUE_NEEDED:

                if (secure_buffer_out[0].cbBuffer > 0)
                {
                    send_and_verify_all_sent(tcp_socket, (const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
                }

                if (sec_status == SEC_E_OK)
                {
                    authn_completed = true;
                }

                if (sec_status == SEC_I_CONTINUE_NEEDED)
                {
                    for (unsigned long i = 1; i < secure_buffer_desc_in.cBuffers; ++i)
                    {
                        SecBuffer& secure_buffer = secure_buffer_in[i];
                        if (secure_buffer.BufferType == SECBUFFER_EXTRA)
                        {
                            // Calculate the beginning of the extra bytes
                            int extra_offset = secure_buffer_in[0].cbBuffer - secure_buffer.cbBuffer;
                            std::cout << "extra_offset: " << extra_offset << std::endl;
                            std::cout << "secure_buffer.cbBuffer: " << secure_buffer.cbBuffer << std::endl;
                            char* extra_bytes = (char*)secure_buffer_in[0].pvBuffer + extra_offset;

                            // Copy to the beginning of the buffer for next time
                            memcpy(secure_buffer_in[0].pvBuffer, extra_bytes, secure_buffer.cbBuffer);
                            recv_offset = secure_buffer.cbBuffer;

                            break;
                        }
                    }
                }

                break;

            case SEC_I_COMPLETE_AND_CONTINUE:
            case SEC_I_COMPLETE_NEEDED:
            {
                SECURITY_STATUS complete_sec_status = SEC_E_OK;
                complete_sec_status = CompleteAuthToken(&security_context_handle, &secure_buffer_desc_out);

                if (complete_sec_status != SEC_E_OK)
                {
                    throw Win32Exception(
                        "establish_client_security_context", "CompleteAuthToken", complete_sec_status
                    );
                }

                if (secure_buffer_out[0].cbBuffer > 0)
                {
                    send_and_verify_all_sent(tcp_socket, (const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
                }

                if (sec_status == SEC_I_COMPLETE_NEEDED)
                {
                    authn_completed = true;
                }

                if (sec_status == SEC_I_COMPLETE_AND_CONTINUE)
                {
                    for (unsigned long i = 1; i < secure_buffer_desc_in.cBuffers; ++i)
                    {
                        SecBuffer& secure_buffer = secure_buffer_in[i];
                        if (secure_buffer.BufferType == SECBUFFER_EXTRA)
                        {
                            // Calculate the beginning of the extra bytes
                            int extra_offset = secure_buffer_in[0].cbBuffer - secure_buffer.cbBuffer;
                            char* extra_bytes = (char*)secure_buffer_in[0].pvBuffer + extra_offset;

                            // Copy to the beginning of the buffer for next time
                            memcpy(secure_buffer_in[0].pvBuffer, extra_bytes, secure_buffer.cbBuffer);
                            recv_offset = secure_buffer.cbBuffer;
                            break;
                        }
                    }
                }

                break;
            }

            default:
                throw Win32Exception(
                    "establish_client_security_context", "InitializeSecurityContext", sec_status
                );
            }
        }
    }
    catch (...)
    {
        SchannelHelper::delete_security_context(&security_context_handle);
        throw;
    }

    return security_context_handle;
}

void SchannelHelper::delete_security_context(SecHandle* security_context)
{
    SECURITY_STATUS sec_status = DeleteSecurityContext(security_context);
    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "delete_security_context", "DeleteSecurityContext", sec_status
        );
    }
}

SecPkgContext_StreamSizes SchannelHelper::get_stream_sizes(SecHandle security_context)
{
    SecPkgContext_StreamSizes stream_sizes = { 0 };

    SECURITY_STATUS sec_status = QueryContextAttributes(
        &security_context,
        SECPKG_ATTR_STREAM_SIZES,
        &stream_sizes
    );

    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "get_stream_sizes", "QueryContextAttributes", sec_status
        );
    }

    return stream_sizes;
}

int SchannelHelper::encrypt_message(SecHandle security_context, SecPkgContext_StreamSizes stream_sizes, const char* in_buf, int in_len, char* out_buf, int out_len)
{
    if (in_len > (int)stream_sizes.cbMaximumMessage)
    {
        throw std::runtime_error("encrypt_message: Message is too long");
    }
    
    int min_out_len = stream_sizes.cbHeader + in_len + stream_sizes.cbTrailer;
    if (min_out_len > out_len)
    {
        throw std::runtime_error("encrypt_message: Output buffer is too small");
    }

    SecBuffer secure_buffers[4] = { 0 };
    init_sec_buffer(secure_buffers[0], SECBUFFER_STREAM_HEADER, stream_sizes.cbHeader, out_buf);
    init_sec_buffer(secure_buffers[1], SECBUFFER_DATA, in_len, out_buf + stream_sizes.cbHeader);
    init_sec_buffer(secure_buffers[2], SECBUFFER_STREAM_TRAILER, stream_sizes.cbTrailer, out_buf + stream_sizes.cbHeader + in_len);
    init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
    
    SecBufferDesc secure_buffer_desc = { 0 };
    init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

    memcpy(secure_buffers[1].pvBuffer, in_buf, in_len);

    SECURITY_STATUS sec_status = EncryptMessage(&security_context, 0, &secure_buffer_desc, 0);

    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "encrypt_message", "EncryptMessage", sec_status
        );
    }

    return min_out_len;
}

int SchannelHelper::decrypt_message(SecHandle security_context, SecPkgContext_StreamSizes stream_sizes, const char* in_buf, int in_len, char* out_buf, int out_len)
{
    int msg_size = in_len - stream_sizes.cbHeader - stream_sizes.cbTrailer;
    if (msg_size > (int)stream_sizes.cbMaximumMessage)
    {
        throw std::runtime_error("decrypt_message: Message to is too long");
    }

    if (msg_size > out_len)
    {
        throw std::runtime_error("decrypt_message: Output buffer is too small");
    }

    auto decrypt_buf = std::make_unique<char[]>(in_len);

    SecBuffer secure_buffers[4] = { 0 };
    init_sec_buffer(secure_buffers[0], SECBUFFER_DATA, in_len, decrypt_buf.get());
    init_sec_buffer(secure_buffers[1], SECBUFFER_EMPTY, 0, nullptr);
    init_sec_buffer(secure_buffers[2], SECBUFFER_EMPTY, 0, nullptr);
    init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
    
    SecBufferDesc secure_buffer_desc = { 0 };
    init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

    // Copy encrypted message to in-out temp buffer
    memcpy(decrypt_buf.get(), in_buf, in_len);

    SECURITY_STATUS sec_status = DecryptMessage(&security_context, &secure_buffer_desc, 0, nullptr);

    if (sec_status == SEC_E_INCOMPLETE_MESSAGE)
    {
        return -1;
    }

    if (sec_status != SEC_E_OK)
    {
        throw Win32Exception(
            "decrypt_message", "DecryptMessage", sec_status
        );
    }

    if ((int)secure_buffers[1].cbBuffer > out_len)
    {
        throw std::runtime_error("decrypt_message: Inconsistent decrypted message size");
    }
    
    memcpy(out_buf, secure_buffers[1].pvBuffer, secure_buffers[1].cbBuffer);
    return secure_buffers[1].cbBuffer;
}
