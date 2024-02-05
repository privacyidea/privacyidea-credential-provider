#pragma once
#include "AllowCredential.h"
#include <string>
#include <vector>

struct WebAuthnSignRequest
{
	std::vector<AllowCredential> allowCredentials;
	std::string challenge;
	std::string rpId;
	std::string userVerification;
	std::vector<std::string> transports;
	std::string type;
	int timeout = 0;
};
