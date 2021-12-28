#pragma once

#include <Windows.h>

#include <string>

struct TLSConfig
{
    DWORD enabled_protocols = 0;
    DWORD cert_store_location = 0;
    std::string cert_store_name;
    std::string cert_subject_match;
};
