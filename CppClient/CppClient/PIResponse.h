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

#pragma once
#include "Challenge.h"
#include "FIDORegistrationRequest.h"
#include "FIDOSignRequest.h"
#include "AuthenticationStatus.h"
#include <optional>
#include <memory>
#include <string>
#include <vector>

class PIResponse
{
public:
	bool status = false;
	bool value = false;
	AuthenticationStatus authenticationStatus = AuthenticationStatus::NOT_SET;
	std::string transactionId;
	std::string message;

	std::string errorMessage;
	int errorCode = 0;

	std::vector<Challenge> challenges;

	bool IsPushAvailable();

	bool isAuthenticationSuccessful() const;

	std::string GetPushMessage();

	std::optional<FIDOSignRequest> GetFIDOSignRequest();

	std::string GetFIDOMessage();

	std::string GetNonFIDOMessage(); // everything except FIDO token

	std::string preferredMode;

	std::optional<std::string> username = std::nullopt;

	std::optional<FIDORegistrationRequest> passkeyRegistration = std::nullopt;

	std::optional<FIDOSignRequest> passkeyChallenge = std::nullopt;

	bool IsVersionHigherOrEqual(int major, int minor = 0, int patch = 0) const;

	int privacyIDEAVersionMajor = 99;
	int privacyIDEAVersionMinor = 99;
	int privacyIDEAVersionPatch = 99;
	std::string privacyIDEAVersionSuffix = ""; // like dev0, beta1

	bool isEnrollViaMultichallenge = false; // true if the response is a multichallenge response, e.g. for FIDO2 registration
	bool isEnrollCancellable = false; // true if the enrollment can be cancelled by the user
};

