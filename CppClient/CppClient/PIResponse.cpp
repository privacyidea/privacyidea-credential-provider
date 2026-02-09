/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
** Author: Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "PIResponse.h"
#include "Logger.h"

bool PIResponse::IsPushAvailable()
{
	for (auto& challenge : challenges)
	{
		if (challenge.type == "push" || challenge.type == "smartphone")
		{
			return true;
		}
	}
	return false;
}

bool PIResponse::isAuthenticationSuccessful() const
{
	if (authenticationStatus == AuthenticationStatus::ACCEPT)
	{
		return true;
	}
	else if (authenticationStatus == AuthenticationStatus::NOT_SET && challenges.empty() && value)
	{
		return true;
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

std::optional<FIDOSignRequest> PIResponse::GetFIDOSignRequest()
{
	std::optional<FIDOSignRequest> ret = std::nullopt;

	bool hasWebAuthn = false;
	bool hasPasskey = false;

	for (const auto& challenge : challenges)
	{
		if (challenge.type == "webauthn") hasWebAuthn = true;
		else if (challenge.type == "passkey") hasPasskey = true;
	}

	std::string targetType = "";
	// Prioritize passkey over webauthn if both are present
	if (hasPasskey)
	{
		targetType = "passkey";
		if (hasWebAuthn)
		{
			PIDebug("WARNING: Received mixed 'webauthn' and 'passkey' challenges.");
			PIDebug("Prioritizing 'passkey' over 'webauthn' as per configuration.");
		}
	}
	else if (hasWebAuthn)
	{
		targetType = "webauthn";
	}
	else
	{
		return std::nullopt;
	}

	std::vector<AllowCredential> accumulatedCredentials;
	FIDOSignRequest baseRequest;
	bool baseRequestInitialized = false;

	for (auto& challenge : challenges)
	{
		if (challenge.type != targetType) continue;

		if (!challenge.fidoSignRequest.has_value()) continue;

		const auto& currentReq = challenge.fidoSignRequest.value();

		if (!currentReq.allowCredentials.empty())
		{
			accumulatedCredentials.insert(
				accumulatedCredentials.end(),
				currentReq.allowCredentials.begin(),
				currentReq.allowCredentials.end()
			);
		}

		// Initialize Base Request from the first valid challenge of the correct type.
		// We ensure we grab the challenge string/RPID from the correct type.
		if (!baseRequestInitialized && !currentReq.rpId.empty())
		{
			baseRequest = currentReq;
			baseRequest.type = targetType;
			baseRequestInitialized = true;
		}
	}

	// Only return if we successfully initialized the base request (have challenge + rpId)
	if (baseRequestInitialized && !baseRequest.challenge.empty())
	{
		// Overwrite credentials with the accumulated list
		// Note: Passkeys typically have empty lists here (unless triggered as token), 
		// but 'insert' handles empty/non-empty correctly regardless.
		baseRequest.allowCredentials = accumulatedCredentials;
		ret = baseRequest;
	}

	return ret;
}

std::string Concatenate(std::vector<std::string> vec)
{
	std::string msg;
	for (auto& m : vec)
	{
		msg += m + ", ";
	}
	// Remove the last comma and space
	if (!msg.empty())
	{
		msg.pop_back();
		msg.pop_back();
	}

	return msg;
}

std::string PIResponse::GetFIDOMessage()
{
	if (challenges.empty())
	{
		return "";
	}
	std::vector<std::string> messages;
	for (auto& challenge : challenges)
	{
		if (std::find(messages.begin(), messages.end(), challenge.message) == messages.end()
			&& (challenge.type == "webauthn" || challenge.type == "passkey"))
		{
			messages.push_back(challenge.message);
		}
	}
	return Concatenate(messages);
}

std::string PIResponse::GetNonFIDOMessage()
{
	if (challenges.empty())
	{
		return "";
	}
	std::vector<std::string> messages;
	for (auto& challenge : challenges)
	{
		if (std::find(messages.begin(), messages.end(), challenge.message) == messages.end()
			&& challenge.type != "webauthn" && challenge.type != "passkey")
		{
			messages.push_back(challenge.message);
		}
	}
	return Concatenate(messages);
}

bool PIResponse::IsVersionHigherOrEqual(int major, int minor, int patch) const
{
	if (privacyIDEAVersionMajor > major)
	{
		return true;
	}
	else if (privacyIDEAVersionMajor == major)
	{
		if (privacyIDEAVersionMinor > minor)
		{
			return true;
		}
		else if (privacyIDEAVersionMinor == minor)
		{
			return privacyIDEAVersionPatch >= patch;
		}
	}
	return false;
}
