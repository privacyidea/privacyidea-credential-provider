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
#include "PIConf.h"
#include <map>
#include <Windows.h>

enum class RequestMethod
{
	GET,
	POST
};

// Endpoint class that connects to privacyIDEA and parses the reponses
class Endpoint
{
public:
	Endpoint(PICONFIG conf);

	std::string SendRequest(const std::string& endpoint, std::string sdata, const RequestMethod& method);

	// URL encodes the value and returns "key=value"
	std::string EncodePair(const std::string& key, const std::string& value);
	std::string EncodePair(const std::string& key, const std::wstring& value);

	HRESULT PollForTransaction(const std::string& data);

	HRESULT FinalizePolling(const std::string& user, const std::string& transaction_id);

	// <returns> EP_STATUS_TX_SUCCESS, EP_STATUS_TX_FAILURE or error from <seealso cref="Endpoint::parseError/> </returns>
	HRESULT ParseForTransactionSuccess(const std::string& in);

	HRESULT ParseAuthenticationRequest(const std::string& in);

	// Checks the server's response for triggered challenges, collect data in c
	// <returns> EP_TRIGGERED_CHALLENGE if data for CR was found,
	//			 EP_NO_CHALLENGE if no data was found or the error from <seealso cref="Endpoint::parseError"/> </returns>
	HRESULT ParseTriggerRequest(const std::string& in, Challenge& c);

	// Check the response for error code and message
	// returns PI_JSON_ERROR_CONTAINED if there was an error and the message and code in the provided parameters
	// or PI_JSON_PARSE_ERROR or S_OK if there was no error
	HRESULT ParseForError(const std::string& in, std::string& errMsg, int& errCode);

	const HRESULT& GetLastErrorCode();

	static nlohmann::json TryParseJSON(const std::string& in);

private:

	std::wstring Get_utf16(const std::string& str, int codepage);

	std::string EscapeUrl(const std::string& in);

	bool _ignoreInvalidCN = false;
	bool _ignoreUnknownCA = false;
	std::wstring _hostname = L"";
	std::wstring _path = L"";
	int _customPort = 0;

	bool _logPasswords = false;

	HRESULT _lastErrorCode = 0;

	// These are the default values for WinHttpSetTimeouts
	int _resolveTimeout = 0; // = infinite
	int _connectTimeout = 60000;
	int _sendTimeout = 30000;
	int _receiveTimeout = 30000;
};

