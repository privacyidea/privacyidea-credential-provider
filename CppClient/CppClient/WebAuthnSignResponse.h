#pragma once
#include <string>

struct WebAuthnSignResponse
{
	std::string credentialid;
	std::string clientdata;
	std::string authenticatordata;
	std::string signaturedata;
	std::string userHandle;
};
