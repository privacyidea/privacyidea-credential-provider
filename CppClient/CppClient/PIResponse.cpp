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
