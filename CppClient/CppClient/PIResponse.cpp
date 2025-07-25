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

std::string PIResponse::GetDeduplicatedMessage()
{
	if (challenges.empty())
	{
		return message;
	}
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
	for (auto& m : messages)
	{
		deduplicatedMessage += m + ", ";
	}
	// Remove the last comma and space
	if (!deduplicatedMessage.empty())
	{
		deduplicatedMessage.pop_back();
		deduplicatedMessage.pop_back();
	}

	return deduplicatedMessage;
}