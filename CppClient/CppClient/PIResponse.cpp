#include "PIResponse.h"

bool PIResponse::IsPushAvailable()
{
	for (auto& challenge : challenges)
	{
		if (challenge.type == "push")
		{
			return true;
		}
	}
	return false;
}

std::string PIResponse::GetPushMessage()
{
	for (auto& challenge : challenges)
	{
		if (challenge.type == "push")
		{
			return challenge.message;
		}
	}
	return "";
}

WebAuthnSignRequest PIResponse::GetWebAuthnSignRequest()
{
	std::vector<AllowCredential> allowCredentials;
	WebAuthnSignRequest webAuthnSignRequest;
	for (auto& challenge : challenges)
	{
		if (challenge.type == "webauthn")
		{
			allowCredentials.push_back(challenge.webAuthnSignRequest.allowCredentials[0]);
			if (webAuthnSignRequest.rpId.empty())
			{
				webAuthnSignRequest = challenge.webAuthnSignRequest;
			}
		}
	}

	if (allowCredentials.size() > 0)
	{
		webAuthnSignRequest.allowCredentials = allowCredentials;
	}

	return webAuthnSignRequest;
}

std::string PIResponse::GetDeduplicatedMessage()
{
	std::vector<std::string> messages;
	// Add the message of each challenge to the vector, only if it is not already in there
	for (auto& challenge : challenges)
	{
		if (std::find(messages.begin(), messages.end(), challenge.message) == messages.end())
		{
			messages.push_back(challenge.message);
		}
	}
	// Concatenate all messages
	std::string deduplicatedMessage;
	for (auto& message : messages)
	{
		deduplicatedMessage += message + ", ";
	}
	// Remove the last comma and space
	if (!deduplicatedMessage.empty())
	{
		deduplicatedMessage.pop_back();
		deduplicatedMessage.pop_back();
	}

	return deduplicatedMessage;
}