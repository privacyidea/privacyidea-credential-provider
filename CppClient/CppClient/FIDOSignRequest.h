#pragma once
#include <string>
#include <vector>

struct AllowCredential
{
	std::string id;
	std::vector<std::string> transports;
	std::string type = "public-key";
};


struct FIDOSignRequest
{
	std::vector<AllowCredential> allowCredentials;
	std::string challenge;
	std::string rpId;
	std::string userVerification;
	std::vector<std::string> transports;
	std::string type; // Token type, "webauthn" or "passkey"
	std::string transactionId;
	std::string message;
	int timeout = 0;

	FIDOSignRequest() = default;

	FIDOSignRequest(
		const std::string& challenge,
		const std::string& rpId,
		const std::string& userVerification,
		const std::string& transactionId,
		const std::string& message,
		const std::string& type,
		const std::vector<AllowCredential>& allowCredentials = std::vector<AllowCredential>(),
		const std::vector<std::string>& transports = std::vector<std::string>(),
		int timeout = 0)
		: challenge(challenge), rpId(rpId), userVerification(userVerification), transactionId(transactionId), message(message),
		type(type), allowCredentials(allowCredentials), transports(transports), timeout(timeout)
	{}

	std::string ToString()
	{
		// convert all non vectors to string and concatenate
		return "FIDO2SignRequest: challenge: " + challenge +
			", rpId: " + rpId +
			", userVerification: " + userVerification +
			", transactionId: " + transactionId +
			", message: " + message +
			", type: " + type ;
	}
};
