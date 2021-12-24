
#pragma comment(lib, "Secur32")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "ws2_32")

#include "schannel.h"

#include <schnlsp.h>

#include <sstream>
#include <memory>

#define BUFFER_SIZE 16384

const CERT_CONTEXT* SchannelHelper::get_certificate()
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

        // TODO: unique_ptr with custom deleter

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

void SchannelHelper::free_cert_context(const CERT_CONTEXT* cert_context)
{
    CertFreeCertificateContext(cert_context);
}

CredHandle SchannelHelper::get_schannel_server_handle(const CERT_CONTEXT* cert_context)
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

CredHandle SchannelHelper::get_schannel_client_handle()
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

void SchannelHelper::free_cred_handle(CredHandle* cred_handle)
{
    SECURITY_STATUS sec_status = FreeCredentialsHandle(cred_handle);
    if (sec_status != SEC_E_OK)
    {
        std::stringstream str_stream;
        str_stream << "FreeCredentialsHandle: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }
}

SecHandle SchannelHelper::establish_server_security_context(CredHandle server_cred_handle, TCPSocket tcp_socket)
{
    SecHandle security_context_handle = { 0 };

    try
    {
        // Input buffer
        auto buffer_in = std::make_unique<char[]>(BUFFER_SIZE);
        SecBuffer secure_buffer_in[2] = { 0 };

        secure_buffer_in[0].BufferType = SECBUFFER_TOKEN;
        secure_buffer_in[0].cbBuffer = BUFFER_SIZE;
        secure_buffer_in[0].pvBuffer = buffer_in.get();

        secure_buffer_in[1].BufferType = SECBUFFER_EMPTY;
        secure_buffer_in[1].cbBuffer = 0;
        secure_buffer_in[1].pvBuffer = nullptr;

        SecBufferDesc secure_buffer_desc_in = { 0 };
        secure_buffer_desc_in.ulVersion = SECBUFFER_VERSION;
        secure_buffer_desc_in.cBuffers = 2;
        secure_buffer_desc_in.pBuffers = secure_buffer_in;

        // Output buffer
        auto buffer_out = std::make_unique<char[]>(BUFFER_SIZE /* + BUFFER_SIZE */);
        SecBuffer secure_buffer_out[1] = { 0 };

        secure_buffer_out[0].BufferType = SECBUFFER_TOKEN;
        secure_buffer_out[0].cbBuffer = BUFFER_SIZE;
        secure_buffer_out[0].pvBuffer = buffer_out.get();

        /*secure_buffer_out[1].BufferType = SECBUFFER_ALERT;
        secure_buffer_out[1].cbBuffer = BUFFER_SIZE;
        secure_buffer_out[1].pvBuffer = buffer_out.get() + BUFFER_SIZE;*/

        SecBufferDesc secure_buffer_desc_out = { 0 };
        secure_buffer_desc_out.ulVersion = SECBUFFER_VERSION;
        secure_buffer_desc_out.cBuffers = 1;
        secure_buffer_desc_out.pBuffers = secure_buffer_out;

        ULONG context_attributes = 0;
        TimeStamp life_time = { 0 };

        secure_buffer_in[0].cbBuffer = tcp_socket.recv((char*)secure_buffer_in[0].pvBuffer, BUFFER_SIZE);

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
            if (secure_buffer_out[0].cbBuffer > 0)
            {
                int sent = tcp_socket.send((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
                if (sent != secure_buffer_out[0].cbBuffer)
                {
                    throw std::runtime_error("send: Unexpected Result");
                }
            }

            if (auth_completed)
            {
                break;
            }

            secure_buffer_in[0].cbBuffer = tcp_socket.recv((char*)secure_buffer_in[0].pvBuffer, BUFFER_SIZE);

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
                std::stringstream str_stream;
                str_stream << "AcceptSecurityContext: " << std::hex << sec_status;
                throw std::runtime_error(str_stream.str());
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

SecHandle SchannelHelper::establish_client_security_context(CredHandle client_cred_handle, const std::string& hostname, TCPSocket tcp_socket)
{
    SecHandle security_context_handle = { 0 };

    try
    {
        // Input buffer
        auto buffer_in = std::make_unique<char[]>(BUFFER_SIZE);
        SecBuffer secure_buffer_in[2] = { 0 };

        secure_buffer_in[0].BufferType = SECBUFFER_TOKEN;
        secure_buffer_in[0].cbBuffer = BUFFER_SIZE;
        secure_buffer_in[0].pvBuffer = buffer_in.get();

        secure_buffer_in[1].BufferType = SECBUFFER_EMPTY;
        secure_buffer_in[1].cbBuffer = 0;
        secure_buffer_in[1].pvBuffer = nullptr;

        SecBufferDesc secure_buffer_desc_in = { 0 };
        secure_buffer_desc_in.ulVersion = SECBUFFER_VERSION;
        secure_buffer_desc_in.cBuffers = 2;
        secure_buffer_desc_in.pBuffers = secure_buffer_in;

        // Output buffer
        auto buffer_out = std::make_unique<char[]>(BUFFER_SIZE /* + BUFFER_SIZE */);
        SecBuffer secure_buffer_out[1] = { 0 };

        secure_buffer_out[0].BufferType = SECBUFFER_TOKEN;
        secure_buffer_out[0].cbBuffer = BUFFER_SIZE;
        secure_buffer_out[0].pvBuffer = buffer_out.get();

        /*secure_buffer_out[1].BufferType = SECBUFFER_ALERT;
        secure_buffer_out[1].cbBuffer = BUFFER_SIZE;
        secure_buffer_out[1].pvBuffer = buffer_out.get() + BUFFER_SIZE;*/

        SecBufferDesc secure_buffer_desc_out = { 0 };
        secure_buffer_desc_out.ulVersion = SECBUFFER_VERSION;
        secure_buffer_desc_out.cBuffers = 1;
        secure_buffer_desc_out.pBuffers = secure_buffer_out;

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
            int sent = tcp_socket.send((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
            if (sent != secure_buffer_out[0].cbBuffer)
            {
                throw std::runtime_error("send: Unexpected Result");
            }

            secure_buffer_in[0].cbBuffer = tcp_socket.recv((char*)secure_buffer_in[0].pvBuffer, BUFFER_SIZE);

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
        std::stringstream str_stream;
        str_stream << "DeleteSecurityContext: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
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
        std::stringstream str_stream;
        str_stream << "QueryContextAttributes: " << std::hex << sec_status;
        throw std::runtime_error(str_stream.str());
    }

    return stream_sizes;
}

int SchannelHelper::encrypt_message(SecHandle security_context, SecPkgContext_StreamSizes stream_sizes, const char* in_buf, int in_len, char* out_buf, int out_len)
{
    if (in_len > (int)stream_sizes.cbMaximumMessage)
    {
        throw std::runtime_error("Message to encrypt is too long");
    }
    
    int min_out_len = stream_sizes.cbHeader + in_len + stream_sizes.cbTrailer;
    if (min_out_len > out_len)
    {
        throw std::runtime_error("Output buffer is too small");
    }

    SecBuffer secure_buffers[4] = { 0 };

    secure_buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    secure_buffers[0].cbBuffer = stream_sizes.cbHeader;
    secure_buffers[0].pvBuffer = out_buf;

    secure_buffers[1].BufferType = SECBUFFER_DATA;
    secure_buffers[1].cbBuffer = in_len;
    secure_buffers[1].pvBuffer = out_buf + stream_sizes.cbHeader;

    secure_buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    secure_buffers[2].cbBuffer = stream_sizes.cbTrailer;
    secure_buffers[2].pvBuffer = out_buf + stream_sizes.cbHeader + in_len;

    secure_buffers[3].BufferType = SECBUFFER_EMPTY;
    secure_buffers[3].cbBuffer = 0;
    secure_buffers[3].pvBuffer = nullptr;
    
    SecBufferDesc secure_buffer_desc = { 0 };
    secure_buffer_desc.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc.cBuffers = 4;
    secure_buffer_desc.pBuffers = secure_buffers;

    memcpy(secure_buffers[1].pvBuffer, in_buf, in_len);

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

    return min_out_len;
}

int SchannelHelper::decrypt_message(SecHandle security_context, SecPkgContext_StreamSizes stream_sizes, const char* in_buf, int in_len, char* out_buf, int out_len)
{
    int msg_size = in_len - stream_sizes.cbHeader - stream_sizes.cbTrailer;
    if (msg_size > (int)stream_sizes.cbMaximumMessage)
    {
        throw std::runtime_error("Message to decrypt is too long");
    }

    if (msg_size > out_len)
    {
        throw std::runtime_error("Output buffer is too small");
    }

    auto decrypt_buf = std::make_unique<char[]>(in_len);

    SecBuffer secure_buffers[4] = { 0 };

    secure_buffers[0].BufferType = SECBUFFER_DATA;
    secure_buffers[0].cbBuffer = in_len;
    secure_buffers[0].pvBuffer = decrypt_buf.get();

    secure_buffers[1].BufferType = SECBUFFER_EMPTY;
    secure_buffers[1].cbBuffer = 0;
    secure_buffers[1].pvBuffer = nullptr;

    secure_buffers[2].BufferType = SECBUFFER_EMPTY;
    secure_buffers[2].cbBuffer = 0;
    secure_buffers[2].pvBuffer = nullptr;

    secure_buffers[3].BufferType = SECBUFFER_EMPTY;
    secure_buffers[3].cbBuffer = 0;
    secure_buffers[3].pvBuffer = nullptr;
    
    SecBufferDesc secure_buffer_desc = { 0 };
    secure_buffer_desc.ulVersion = SECBUFFER_VERSION;
    secure_buffer_desc.cBuffers = 4;
    secure_buffer_desc.pBuffers = secure_buffers;

    // Copy encrypted message to in-out temp buffer
    memcpy(decrypt_buf.get(), in_buf, in_len);

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

    if ((int)secure_buffers[1].cbBuffer > out_len)
    {
        throw std::runtime_error("Inconsistent decrypted message size");
    }
    
    memcpy(out_buf, secure_buffers[1].pvBuffer, secure_buffers[1].cbBuffer);
    return secure_buffers[1].cbBuffer;
}
