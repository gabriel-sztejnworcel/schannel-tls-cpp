#pragma once

#include <Windows.h>

#include <string>

namespace schannel {

struct TLSConfig
{
    DWORD enabled_protocols = 0;
    DWORD cert_store_location = 0;
    std::string cert_store_name;
    std::string cert_subject_match;
    bool verify_server_cert = true;
};

}; // namespace schannel
