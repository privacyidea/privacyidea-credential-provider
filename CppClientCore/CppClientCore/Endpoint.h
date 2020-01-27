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
#include <string>
#include <map>
#include <Windows.h>

enum class RequestMethod {
	GET,
	POST
};

// Endpoint class that connects to privacyIDEA as well as parsing the reponses
class Endpoint
{
public:
	Endpoint() = default;

	Endpoint(std::wstring& hostname, std::wstring& path, int customPort, bool ignoreInvalidCN, bool ignoreUnknownCA, bool logPasswords) :
		_hostname(std::move(hostname)), _path(std::move(path)), _customPort(customPort), _ignoreInvalidCN(ignoreInvalidCN),
		_ignoreUnknownCA(ignoreUnknownCA), _logPasswords(logPasswords) {};

	~Endpoint() = default;

	std::string connect(const std::string& endpoint, std::map<std::string, std::string> params, const RequestMethod& method);

	HRESULT pollForTransaction(const std::map<std::string, std::string>& params);

	HRESULT finalizePolling(const std::string& user, const std::string& transaction_id);

	// <returns> EP_STATUS_TX_SUCCESS, EP_STATUS_TX_FAILURE or error from <seealso cref="Endpoint::parseError/> </returns>
	HRESULT parseForTransactionSuccess(const std::string& in);

	HRESULT parseAuthenticationRequest(const std::string& in);

	// Checks the server's response for triggered challenges, collect data in c
	// <returns> EP_TRIGGERED_CHALLENGE if data for CR was found,
	//			 EP_NO_CHALLENGE if no data was found or the error from <seealso cref="Endpoint::parseError"/> </returns>
	HRESULT parseTriggerRequest(const std::string& in, Challenge& c);

	// Check the response for error code and message
	// returns EP_ERROR_CONTAINED if there was an error or S_OK if not
	HRESULT parseForError(const std::string& in);

private:

	std::wstring get_utf16(const std::string& str, int codepage);

	std::string escapeUrl(const std::string& in);

	bool _ignoreInvalidCN = false;
	bool _ignoreUnknownCA = false;
	std::wstring _hostname = L"";
	std::wstring _path = L"";
	int _customPort = 0;

	bool _logPasswords = false;
};

