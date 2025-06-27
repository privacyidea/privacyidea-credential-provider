/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2019 NetKnights GmbH
** Author:		Nils Behlen
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

#include "Logger.h"
#include <map>

class OfflineData
{
public:
	int GetLowestKey();

	bool operator==(const OfflineData& other) const
	{
		return username == other.username && serial == other.serial && refilltoken == other.refilltoken;
	}

	std::string username = "";
	std::string serial = "";
	std::string refilltoken = "";

	// HOTP
	std::map<std::string, std::string> offlineOTPs;
	int rounds = 10000;
	int count = 0; // Max OTPs that will be stored offline

	// WebAuthn
	std::string pubKey;
	std::string credId;
	std::string rpId;

	bool isWebAuthn() const noexcept { return !pubKey.empty() && !credId.empty() && !rpId.empty(); }
};
