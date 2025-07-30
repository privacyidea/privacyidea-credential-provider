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
	std::vector<AllowCredential> allowCredentials;
	FIDOSignRequest signRequest;
	for (auto& challenge : challenges)
	{
		if (challenge.type == "webauthn" || challenge.type == "passkey")
		{
			if (challenge.type == "webauthn" && challenge.fidoSignRequest
				&& !challenge.fidoSignRequest.value().allowCredentials.empty())
			{
				allowCredentials.push_back(challenge.fidoSignRequest.value().allowCredentials.at(0));
			}
			// Set the RP ID only once
			if (signRequest.rpId.empty())
			{
				signRequest = challenge.fidoSignRequest.value();
			}
		}
	}

	if (!signRequest.challenge.empty() && !signRequest.rpId.empty())
	{
		signRequest.allowCredentials = allowCredentials;
		ret = signRequest;
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

bool PIResponse::IsVersionHigherThan(int major, int minor, int patch) const
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
			return privacyIDEAVersionPatch > patch;
		}
	}
	return false;
}
