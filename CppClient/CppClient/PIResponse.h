/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
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
#include "WebAuthnSignRequest.h"
#include <memory>
#include <string>
#include <vector>

class PIResponse
{
public:
	bool status = false;
	bool value = false;

	std::string transactionId;
	std::string message;

	std::string errorMessage;
	int errorCode = 0;

	std::vector<Challenge> challenges;

	bool IsPushAvailable();

	std::string GetPushMessage();

	WebAuthnSignRequest GetWebAuthnSignRequest();

	std::string GetDeduplicatedMessage();

	std::string preferredMode;
};

