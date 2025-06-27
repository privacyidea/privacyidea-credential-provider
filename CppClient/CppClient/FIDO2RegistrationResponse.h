#pragma once
#include <string>

class FIDO2RegistrationResponse
{
public:
	std::string credentialId = "";
	std::string credentialIdRaw = "";
	std::string authenticatorAttachment = "";
	std::string clientDataJSON = "";
	std::string attestationObject = "";
};