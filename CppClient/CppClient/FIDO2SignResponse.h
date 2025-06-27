#pragma once
#include <string>

struct FIDO2SignResponse
{
	std::string credentialid;
	std::string clientdata;
	std::string authenticatordata;
	std::string signaturedata;
	std::string userHandle;
};
