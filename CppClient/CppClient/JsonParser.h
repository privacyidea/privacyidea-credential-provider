/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024 NetKnights GmbH
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
#include "PIResponse.h"
#include "OfflineData.h"
#include <string>
#include <vector>
#include <winerror.h>

#define PI_JSON_PARSE_ERROR							((HRESULT)0x88809031)
constexpr auto JSON_DUMP_INDENTATION = 4;

class JsonParser
{
public:
	/// <summary>
	/// Parse the contents of a privacyIDEA response into an object.
	/// </summary>
	/// <param name="serverResponse"></param>
	/// <param name="responseObj"></param>
	/// <returns>
	/// S_OK success, 
	/// PI_JSON_PARSE_ERROR if the input is malformed or a required field is missing
	/// </returns>
	HRESULT ParseResponse(std::string serverResponse, PIResponse &response);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="input"></param>
	/// <returns></returns>
	std::vector<OfflineData> ParseResponseForOfflineData(std::string input);

	/// <summary>
	/// The format of the saved file differs from the server response. Therefore it should be parsed with this method.
	/// </summary>
	/// <param name="input"></param>
	/// <returns></returns>
	std::vector<OfflineData> ParseFileContentsForOfflineData(std::string input);

	HRESULT ParseOfflineDataItemFromString(std::string input, OfflineData& data);

	std::string OfflineDataToString(std::vector<OfflineData> data);

	bool ParsePollTransaction(std::string input);

	HRESULT ParseRefillResponse(const std::string& in, const std::string& username, OfflineData& data);

	std::string GetRefilltoken(std::string input);


	// Return the input json with indentation of 4. If the input is not a valid json it is returned as is.
	static std::string PrettyFormatJson(std::string input);

	/// <summary>
	/// Check if result->error->code is 905.
	/// If that is the case, the token has been unmarked from being used offline and this function returns false.
	/// If there is an error, return true to keep the token.
	/// </summary>
	/// <param name="input"></param>
	/// <returns>true if still marked for offline or error, false if not</returns>
	bool IsStillActiveOfflineToken(const std::string& input);
};

