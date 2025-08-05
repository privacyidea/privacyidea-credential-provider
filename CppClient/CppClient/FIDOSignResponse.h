#pragma once
#include <string>

struct FIDOSignResponse
{
	std::string credentialid;
	std::string clientdata;
	std::string authenticatordata;
	std::string signaturedata;
	std::string userHandle;
};
