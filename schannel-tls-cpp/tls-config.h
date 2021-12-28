/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#include <Windows.h>

#include <string>

namespace schannel {

struct TLSConfig
{
    /**
     * Enabled TLS protocol versions, for example: SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER.
     * The options are defined in Windows' schannel.h header.
     */
    DWORD enabled_protocols = 0;

    /**
     * Server certificate location, for example: CERT_SYSTEM_STORE_CURRENT_USER.
     * The options are defined in wincrypt.h, include Windows.h to get it.
     */
    DWORD cert_store_location = 0;

    /**
     * The certificate store name, for example: "My" for the personal store.
     */
    std::string cert_store_name;

    /**
     * Subject name.
     * The first certificate in the store that CONTAINS this string in its subject
     * name will be retrieved.
     */
    std::string cert_subject_match;

    /**
     * Verify the server certificate.
     * Verification should be skipped only in dev/debug.
     */
    bool verify_server_cert = true;
};

}; // namespace schannel
