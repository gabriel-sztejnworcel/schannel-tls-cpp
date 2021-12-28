/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#include "tls-server.h"
#include "schannel-helper.h"

using namespace schannel;

TLSServer::TLSServer(const TLSConfig& tls_config) :
    tls_config_(tls_config), cert_context_(nullptr), server_cred_handle_({ 0 })
{

}

TLSServer::~TLSServer()
{
    if (cert_context_ != nullptr)
    {
        SchannelHelper::free_cert_context(cert_context_);
        SchannelHelper::free_cred_handle(&server_cred_handle_);
    }
}

void TLSServer::listen(const std::string& hostname, short port)
{
    tcp_server_.listen(hostname, port);

    cert_context_ = SchannelHelper::get_certificate(tls_config_.cert_store_location, tls_config_.cert_store_name, tls_config_.cert_subject_match);
    server_cred_handle_ = SchannelHelper::get_schannel_server_handle(cert_context_, tls_config_.enabled_protocols);
}

TLSSocket TLSServer::accept()
{
    auto tcp_socket = tcp_server_.accept();
    SecHandle security_context = SchannelHelper::establish_server_security_context(server_cred_handle_, tcp_socket);
    return TLSSocket(tcp_socket, security_context);
}

void TLSServer::close()
{
    tcp_server_.close();
}
