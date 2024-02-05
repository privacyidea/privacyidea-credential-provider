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
#include "PIConfig.h"
#include <map>
#include <Windows.h>

#define PI_ERROR_SERVER_UNAVAILABLE					((HRESULT)0x88809014)
#define PI_ERROR_ENDPOINT_SETUP						((HRESULT)0x88809015)

enum class RequestMethod
{
	GET,
	POST
};

class Endpoint
{ 
public:
	Endpoint(PIConfig config) : _config(config) {};

	std::string SendRequest(
		const std::string& endpoint,
		const std::map<std::string, std::string>& parameters,
		const std::map<std::string, std::string>& headers = std::map<std::string, std::string>(),
		const RequestMethod& method = RequestMethod::POST);

	HRESULT GetLastErrorCode();

private:

	std::string EncodeRequestParameters(const std::map<std::string, std::string>& parameters);

	std::wstring EncodeUTF16(const std::string& str, int codepage);

	std::string URLEncode(const std::string& in);

	HRESULT _lastErrorCode = 0;

	PIConfig _config;
};

