#pragma once
#include <string>
#include <vector>
#include <map>

class FIDO2RegistrationRequest
{
public:
	std::string rpId = "";
	std::string rpName = "";
	std::string userName = "";
	std::string userDisplayName = "";
	std::string userId = "";
	std::string challenge = "";
	std::string serial = "";
	std::string transactionId = "";
	// List of {"type", identifier}, e.g. {"public-key", "-7"} for ES256
	std::vector<std::pair<std::string, int>> pubKeyCredParams;
	std::vector<std::string> excludeCredentials;
	std::string attestation = "none";
	// residentKey, requireResidentKey, userVerification, ...
	std::vector<std::map<std::string, std::string>> authenticatorSelection;
	bool residentKey = true;
	bool userVerification = true;

	int timeout = 120000;
};