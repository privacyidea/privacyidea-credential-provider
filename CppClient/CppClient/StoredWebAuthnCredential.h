#pragma once
#include <string>

namespace privacyidea
{
	struct StoredWebAuthnCredential
	{
		std::string user;
		std::string domain;
		std::string serial;
		std::string cosePublicKey;
		std::string credentialId;
		std::string rpId;
		std::vector<std::string> transports;
		std::string type = "public-key";
		int timeout = 60000;
		std::string userVerification;
		int signCount = 0;
	};
}
