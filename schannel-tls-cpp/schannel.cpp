
#pragma comment(lib, "Secur32")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "ws2_32")

#include "schannel.h"

#include <schnlsp.h>

#include <sstream>
#include <memory>

#define BUFFER_SIZE 16384

const CERT_CONTEXT* get_certificate()
{
    HCERTSTORE personal_cert_store = nullptr;
    const CERT_CONTEXT* cert_context = nullptr;

    try
    {
        personal_cert_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            X509_ASN_ENCODING,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"My"
        );

        if (personal_cert_store == nullptr)
        {
            throw std::runtime_error("CertOpenStore: " + std::to_string(GetLastError()));
        }

        cert_context = CertFindCertificateInStore(
            personal_cert_store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            nullptr,
            nullptr
        );

        if (cert_context == nullptr)
        {
            throw std::runtime_error("CertFindCertificateInStore: " + std::to_string(GetLastError()));
        }
    }
    catch (...)
    {
        if (personal_cert_store != nullptr)
        {
            CertCloseStore(personal_cert_store, 0);
        }

        throw;
    }

    CertCloseStore(personal_cert_store, 0);

    return cert_context;
}

CredHandle get_schannel_server_handle(const CERT_CONTEXT* cert_context)
{
    SCHANNEL_CRED cred_data = { 0 };
    cred_data.dwVersion = SCHANNEL_CRED_VERSION;
    cred_data.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    cred_data.paCred = &cert_context;
    cred_data.cCreds = 1;

    CredHandle cred_handle;
    TimeStamp life_time;
    wchar_t unisp_name[] = UNISP_NAME;

    SECURITY_STATUS sec_status = AcquireCredentialsHandle(
        nullptr,
        unisp_name,
        SECPKG_CRED_INBOUND,
        nullptr,
        &cred_data,
        nullptr,
        nullptr,
        &cred_handle,
        &life_time
    );

    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "AcquireCredentialsHandle: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    return cred_handle;
}

CredHandle get_schannel_client_handle()
{
    SCHANNEL_CRED cred_data = { 0 };
    cred_data.dwVersion = SCHANNEL_CRED_VERSION;
    cred_data.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

    CredHandle cred_handle;
    TimeStamp life_time;
    wchar_t unisp_name[] = UNISP_NAME;

    SECURITY_STATUS sec_status = AcquireCredentialsHandle(
        nullptr,
        unisp_name,
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &cred_data,
        nullptr,
        nullptr,
        &cred_handle,
        &life_time
    );

    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "AcquireCredentialsHandle: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    return cred_handle;
}

SecHandle establish_server_security_context(CredHandle server_cred_handle, SOCKET sock)
{
    SecHandle security_context_handle = { 0 };

    // Input buffer
    auto buffer_in = std::make_unique<char[]>(BUFFER_SIZE);
    SecBuffer secure_buffer_in = { 0 };
    secure_buffer_in.BufferType = SECBUFFER_TOKEN;
    secure_buffer_in.cbBuffer = BUFFER_SIZE;
    secure_buffer_in.pvBuffer = buffer_in.get();

    SecBufferDesc secure_buffer_desc_in = { 0 };
    secure_buffer_desc_in.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc_in.cBuffers = 1;
    secure_buffer_desc_in.pBuffers = &secure_buffer_in;

    // Output buffer
    auto buffer_out = std::make_unique<char[]>(BUFFER_SIZE);
    SecBuffer secure_buffer_out = { 0 };
    secure_buffer_out.BufferType = SECBUFFER_TOKEN;
    secure_buffer_out.cbBuffer = BUFFER_SIZE;
    secure_buffer_out.pvBuffer = buffer_out.get();

    SecBufferDesc secure_buffer_desc_out = { 0 };
    secure_buffer_desc_out.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc_out.cBuffers = 1;
    secure_buffer_desc_out.pBuffers = &secure_buffer_out;

    ULONG context_attributes = 0;
    TimeStamp life_time = { 0 };

    secure_buffer_in.cbBuffer = tcp_recv(sock, (char*)secure_buffer_in.pvBuffer, BUFFER_SIZE);

    SECURITY_STATUS sec_status = AcceptSecurityContext(
        &server_cred_handle,
        nullptr,
        &secure_buffer_desc_in,
        ASC_REQ_CONFIDENTIALITY,
        0,
        &security_context_handle,
        &secure_buffer_desc_out,
        &context_attributes,
        &life_time
    );

    if (sec_status != SEC_I_CONTINUE_NEEDED)
    {
        std::stringstream str_stream;
        str_stream << "AcceptSecurityContext: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    bool auth_completed = false;
    while (true)
    {
        if (secure_buffer_out.cbBuffer > 0)
        {
            int sent = tcp_send(sock, (const char*)secure_buffer_out.pvBuffer, secure_buffer_out.cbBuffer);
            if (sent != secure_buffer_out.cbBuffer)
            {
                throw std::runtime_error("send: Unexpected Result");
            }
        }

        if (auth_completed)
        {
            break;
        }

        secure_buffer_in.cbBuffer = tcp_recv(sock, (char*)secure_buffer_in.pvBuffer, BUFFER_SIZE);

        SECURITY_STATUS sec_status = AcceptSecurityContext(
            &server_cred_handle,
            &security_context_handle,
            &secure_buffer_desc_in,
            ASC_REQ_CONFIDENTIALITY,
            0,
            &security_context_handle,
            &secure_buffer_desc_out,
            &context_attributes,
            &life_time
        );

        SECURITY_STATUS complete_sec_status = SEC_E_OK;

        switch (sec_status)
        {
        case SEC_I_COMPLETE_AND_CONTINUE:
        case SEC_I_COMPLETE_NEEDED:

            complete_sec_status = CompleteAuthToken(
                &security_context_handle,
                &secure_buffer_desc_out
            );

            if (complete_sec_status != SEC_E_OK)
            {
                throw std::runtime_error("CompleteAuthToken: " + std::to_string(complete_sec_status));
            }

            if (sec_status == SEC_I_COMPLETE_NEEDED)
            {
                auth_completed = true;
            }

            break;

        case SEC_I_CONTINUE_NEEDED:
            // Nothing, another iteration
            break;

        case SEC_E_OK:
            auth_completed = true;
            break;

        default:
            throw std::runtime_error("AcceptSecurityContext: " + std::to_string(complete_sec_status));
            break;
        }
    }

    return security_context_handle;
}

SecHandle establish_client_security_context(CredHandle client_cred_handle, const std::string& hostname, SOCKET sock)
{
    SecHandle security_context_handle = { 0 };

    // Input buffer
    auto buffer_in = std::make_unique<char[]>(BUFFER_SIZE);
    SecBuffer secure_buffer_in = { 0 };
    secure_buffer_in.BufferType = SECBUFFER_TOKEN;
    secure_buffer_in.cbBuffer = BUFFER_SIZE;
    secure_buffer_in.pvBuffer = buffer_in.get();

    SecBufferDesc secure_buffer_desc_in = { 0 };
    secure_buffer_desc_in.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc_in.cBuffers = 1;
    secure_buffer_desc_in.pBuffers = &secure_buffer_in;

    // Output buffer
    auto buffer_out = std::make_unique<char[]>(BUFFER_SIZE);
    SecBuffer secure_buffer_out = { 0 };
    secure_buffer_out.BufferType = SECBUFFER_TOKEN;
    secure_buffer_out.cbBuffer = BUFFER_SIZE;
    secure_buffer_out.pvBuffer = buffer_out.get();

    SecBufferDesc secure_buffer_desc_out = { 0 };
    secure_buffer_desc_out.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc_out.cBuffers = 1;
    secure_buffer_desc_out.pBuffers = &secure_buffer_out;

    ULONG context_attributes = 0;
    TimeStamp life_time = { 0 };

    std::wstring hostname_wstr(hostname.begin(), hostname.end());

    SECURITY_STATUS sec_status = InitializeSecurityContext(
        &client_cred_handle,
        nullptr,
        (wchar_t*)hostname_wstr.c_str(),
        ISC_REQ_CONFIDENTIALITY,
        0,
        SECURITY_NATIVE_DREP,
        nullptr,
        0,
        &security_context_handle,
        &secure_buffer_desc_out,
        &context_attributes,
        &life_time
    );

    if (sec_status != SEC_I_CONTINUE_NEEDED)
    {
        std::stringstream str_stream;
        str_stream << "InitializeSecurityContext: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    bool auth_completed = false;
    while (!auth_completed)
    {
        int sent = tcp_send(sock, (const char*)secure_buffer_out.pvBuffer, secure_buffer_out.cbBuffer);
        if (sent != secure_buffer_out.cbBuffer)
        {
            throw std::runtime_error("send: Unexpected Result");
        }

        secure_buffer_in.cbBuffer = tcp_recv(sock, (char*)secure_buffer_in.pvBuffer, BUFFER_SIZE);

        SECURITY_STATUS sec_status = InitializeSecurityContext(
            &client_cred_handle,
            &security_context_handle,
            (wchar_t*)hostname_wstr.c_str(),
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION,
            0,
            SECURITY_NATIVE_DREP,
            &secure_buffer_desc_in,
            0,
            &security_context_handle,
            &secure_buffer_desc_out,
            &context_attributes,
            &life_time
        );

        SECURITY_STATUS complete_sec_status = SEC_E_OK;

        switch (sec_status)
        {
        case SEC_I_COMPLETE_AND_CONTINUE:
        case SEC_I_COMPLETE_NEEDED:

            complete_sec_status = CompleteAuthToken(
                &security_context_handle,
                &secure_buffer_desc_out
            );

            if (complete_sec_status != SEC_E_OK)
            {
                throw std::runtime_error("CompleteAuthToken: " + std::to_string(complete_sec_status));
            }

            if (sec_status == SEC_I_COMPLETE_NEEDED)
            {
                auth_completed = true;
            }

            break;

        case SEC_I_CONTINUE_NEEDED:
            // Nothing, another iteration
            break;

        case SEC_I_INCOMPLETE_CREDENTIALS:
            throw std::runtime_error("InitializeSecurityContext: Incomplete Credentials");
            break;

        case SEC_E_INCOMPLETE_MESSAGE:
            throw std::runtime_error("InitializeSecurityContext: Incomplete Message");
            break;

        case SEC_E_OK:
            auth_completed = true;
            break;
        }
    }

    return security_context_handle;
}

SecPkgContext_StreamSizes get_stream_sizes(SecHandle security_context)
{
    SecPkgContext_StreamSizes stream_sizes = { 0 };

    SECURITY_STATUS sec_status = QueryContextAttributes(
        &security_context,
        SECPKG_ATTR_STREAM_SIZES,
        &stream_sizes
    );

    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "QueryContextAttributes: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    return stream_sizes;
}

Buffer encrypt_message(const char* buf, size_t len, const SecPkgContext_StreamSizes& stream_sizes, SecHandle security_context)
{
    unsigned long msg_size = min((unsigned long)len, stream_sizes.cbMaximumMessage);
    unsigned long buffer_size = stream_sizes.cbHeader + msg_size + stream_sizes.cbTrailer;
    auto encrypt_buf = std::make_unique<char[]>(buffer_size);

    SecBuffer secure_buffers[] = {
        { stream_sizes.cbHeader, SECBUFFER_STREAM_HEADER, encrypt_buf.get() },
        { msg_size, SECBUFFER_DATA, encrypt_buf.get() + stream_sizes.cbHeader },
        { stream_sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, encrypt_buf.get() + stream_sizes.cbHeader + msg_size },
        { 0, SECBUFFER_EMPTY, nullptr }
    };

    SecBufferDesc secure_buffer_desc = { 0 };
    secure_buffer_desc.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc.cBuffers = 4;
    secure_buffer_desc.pBuffers = secure_buffers;

    memset(encrypt_buf.get(), 0, buffer_size);
    memcpy(secure_buffers[1].pvBuffer, buf, msg_size);

    SECURITY_STATUS sec_status = EncryptMessage(
        &security_context,
        0,
        &secure_buffer_desc,
        0
    );

    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "EncryptMessage: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    return Buffer{ std::move(encrypt_buf), buffer_size };
}

Buffer decrypt_message(const char* buf, size_t len, const SecPkgContext_StreamSizes& stream_sizes, SecHandle security_context)
{
    unsigned long msg_size = min((unsigned long)len, stream_sizes.cbMaximumMessage);
    auto decrypt_buf = std::make_unique<char[]>(msg_size);

    SecBuffer secure_buffers[] = {
        { (unsigned long)len, SECBUFFER_DATA, decrypt_buf.get() },
        { 0, SECBUFFER_EMPTY, nullptr },
        { 0, SECBUFFER_EMPTY, nullptr },
        { 0, SECBUFFER_EMPTY, nullptr }
    };

    SecBufferDesc secure_buffer_desc = { 0 };
    secure_buffer_desc.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc.cBuffers = 4;
    secure_buffer_desc.pBuffers = secure_buffers;

    memset(decrypt_buf.get(), 0, msg_size);
    memcpy(decrypt_buf.get(), buf, msg_size);

    SECURITY_STATUS sec_status = DecryptMessage(
        &security_context,
        &secure_buffer_desc,
        0,
        nullptr
    );

    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "DecryptMessage: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    Buffer return_buffer;
    return_buffer.size = secure_buffers[1].cbBuffer;
    return_buffer.data = std::make_unique<char[]>(return_buffer.size);
    memcpy(return_buffer.data.get(), secure_buffers[1].pvBuffer, return_buffer.size);
    
    return return_buffer;
}
