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
#include <string>
#include <vector>

// Data specific to one credential found on the device
struct FIDOAssertionData
{
	std::string credentialid;
	std::string authenticatordata;
	std::string signaturedata;
	std::string userHandle;
	std::string username;
	std::string displayName;
};

struct FIDOSignResponse
{
	// The client data is the same for all assertions
	std::string clientdata;
	std::vector<FIDOAssertionData> assertions;
};