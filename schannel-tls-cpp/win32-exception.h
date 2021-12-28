/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#pragma once

#include <stdexcept>
#include <string>

namespace schannel {

class Win32Exception : public std::exception
{
public:
    Win32Exception(const std::string& calling_function_name, const std::string& function_name, int error_code);
    char const* what() const override;

private:
    std::string msg_;
};

}; // namespace schannel
