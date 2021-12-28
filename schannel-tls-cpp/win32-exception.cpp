/**
* schannel-tls-cpp
* Copyright (c) 2021 Gabriel Sztejnworcel
*/

#include "win32-exception.h"

#include <sstream>

using namespace schannel;

Win32Exception::Win32Exception(const std::string& calling_function_name, const std::string& function_name, int error_code)
{
    std::stringstream str_stream;
    str_stream << calling_function_name << ": Win32 error " << error_code << " in function '" << function_name << "'";
    msg_ = str_stream.str();
}

char const* Win32Exception::what() const
{
    return msg_.c_str();
}
