#pragma once
#include <stdexcept>
#include <string>
#include "fido/err.h"

class FIDOException : public std::runtime_error
{
public:
	explicit FIDOException(int fido_err_code, const std::string& message = "")
		: std::runtime_error(
			message.empty() ?
			"FIDO2 Error: " + std::string(fido_strerr(fido_err_code)) + " (Code: " + std::to_string(fido_err_code) + ")" :
			message + " (FIDO2 Code: " + std::to_string(fido_err_code) + ", " + std::string(fido_strerr(fido_err_code)) + ")"
		),
		_fido_error_code(fido_err_code)
	{}

	explicit FIDOException(const std::string& message)
		: std::runtime_error(message), _fido_error_code(FIDO_ERR_INTERNAL)
	{}


	int getErrorCode() const noexcept
	{
		return _fido_error_code;
	}

private:
	int _fido_error_code;
};