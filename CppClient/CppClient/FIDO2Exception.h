#pragma once
#include <stdexcept>
#include <string>
#include "fido/err.h"

class FIDO2Exception : public std::runtime_error
{
public:
    // Constructor that takes the libfido2 error code and an optional message
    explicit FIDO2Exception(int fido_err_code, const std::string& message = "")
        : std::runtime_error(
            message.empty() ?
            "FIDO2 Error: " + std::string(fido_strerr(fido_err_code)) + " (Code: " + std::to_string(fido_err_code) + ")" :
            message + " (FIDO2 Code: " + std::to_string(fido_err_code) + ", " + std::string(fido_strerr(fido_err_code)) + ")"
        ),
        fido_error_code_(fido_err_code)
    {}

    // Constructor for cases where there's no direct libfido2 error code
    explicit FIDO2Exception(const std::string& message)
        : std::runtime_error(message), fido_error_code_(FIDO_ERR_INTERNAL) // Or some specific internal error code
    {}


    int getFIDOErrorCode() const noexcept
    {
        return fido_error_code_;
    }

private:
    int fido_error_code_;
};