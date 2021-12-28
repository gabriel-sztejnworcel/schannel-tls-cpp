/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#include "tls-client.h"
#include "schannel-helper.h"

using namespace schannel;

TLSClient::TLSClient(TLSConfig tls_config) :
    tls_config_(tls_config)
{
    client_cred_handle_ = SchannelHelper::get_schannel_client_handle(tls_config_.enabled_protocols);
}

TLSClient::~TLSClient()
{
    SchannelHelper::free_cred_handle(&client_cred_handle_);
}

TLSSocket TLSClient::connect(const std::string& hostname, short port)
{
    auto tcp_socket = tcp_client.connect(hostname, port);

    SecHandle security_context = SchannelHelper::establish_client_security_context(
        client_cred_handle_, hostname, tcp_socket, tls_config_.verify_server_cert
    );

    return TLSSocket(tcp_socket, security_context);
}
