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

#include "Convert.h"
#include "JsonParser.h"
#include "Logger.h"
#include "nlohmann/json.hpp"
#include "WebAuthnSignRequest.h"

using json = nlohmann::json;
using namespace std;

int GetIntOrZero(json& input, string fieldName)
{
	auto& t = input[fieldName];
	if (t.is_number_integer())
	{
		return t.get<int>();
	}
	else
	{
		PIDebug(fieldName + " was expected to be int, but was not.");
	}
	return 0;
}

string GetStringOrEmpty(json& input, string fieldName)
{
	auto& t = input[fieldName];
	if (t.is_string())
	{
		return t.get<string>();
	}
	else
	{
		PIDebug(fieldName + " was expected to be string, but was not.");
	}
	return "";
}

bool GetBoolOrFalse(json& input, string fieldName)
{
	auto& t = input[fieldName];
	if (t.is_boolean())
	{
		return t.get<bool>();
	}
	else
	{
		PIDebug(fieldName + " was expected to be bool, but was not.");
	}
	return false;
}

json ParseJson(std::string input)
{
	json jRoot;
	try
	{
		jRoot = json::parse(input);
	}
	catch (const json::parse_error& e)
	{
		PIDebug(e.what());
		return nullptr;
	}
	return jRoot;
}

HRESULT JsonParser::ParseResponse(std::string serverResponse, PIResponse& response)
{
	PIDebug(__FUNCTION__);
	json jRoot;
	try
	{
		jRoot = json::parse(serverResponse);
	}
	catch (const json::parse_error& e)
	{
		PIDebug(e.what());
		return PI_JSON_PARSE_ERROR;
	}

	if (jRoot.contains("result"))
	{
		auto& jResult = jRoot["result"];

		response.value = GetBoolOrFalse(jResult, "value");
		response.status = GetBoolOrFalse(jResult, "status");

		if (jResult.contains("error"))
		{
			auto& jError = jResult["error"];
			response.errorCode = jError["code"].get<int>();
			response.errorMessage = GetStringOrEmpty(jError, "message");
		}
	}
	else
	{
		PIDebug("Reponse did not contain 'result'");
		return PI_JSON_PARSE_ERROR;
	}

	auto& jDetail = jRoot["detail"];

	response.message = GetStringOrEmpty(jDetail, "message");

	auto& multiChallenge = jDetail["multi_challenge"];
	if (!multiChallenge.empty())
	{
		response.transactionId = GetStringOrEmpty(jDetail, "transaction_id");
		response.preferredMode = GetStringOrEmpty(jDetail, "preferred_client_mode");

		for (auto& item : multiChallenge.items())
		{
			json jChallenge = item.value();
			string type = GetStringOrEmpty(jChallenge, "type");
			Challenge c;
			c.type = type;
			c.message = GetStringOrEmpty(jChallenge, "message");
			c.serial = GetStringOrEmpty(jChallenge, "serial");
			c.transactionId = GetStringOrEmpty(jChallenge, "transaction_id");
			c.image = GetStringOrEmpty(jChallenge, "image");

			if (type == "webauthn")
			{
				auto& jSignRequest = jChallenge["attributes"]["webAuthnSignRequest"];
				vector<AllowCredential> allowCredentials;
				for (auto& tmp : jSignRequest["allowCredentials"])
				{
					AllowCredential ac;
					ac.id = GetStringOrEmpty(tmp, "id");
					ac.type = GetStringOrEmpty(tmp, "type");
					for (auto& transport : tmp["transports"])
					{
						ac.transports.push_back(transport.get<string>());
					}
					allowCredentials.push_back(ac);
				}
				WebAuthnSignRequest signRequest;
				signRequest.challenge = GetStringOrEmpty(jSignRequest, "challenge");
				signRequest.rpId = GetStringOrEmpty(jSignRequest, "rpId");
				signRequest.userVerification = GetStringOrEmpty(jSignRequest, "userVerification");
				signRequest.timeout = GetIntOrZero(jSignRequest, "timeout");
				signRequest.allowCredentials = allowCredentials;
				signRequest.type = allowCredentials[0].type; // TODO does this matter? Currently not
				c.webAuthnSignRequest = signRequest;
			}

			response.challenges.push_back(c);
		}
	}

	return S_OK;
}

std::string JsonParser::PrettyFormatJson(std::string input)
{
	json jRoot;
	try
	{
		jRoot = json::parse(input);
	}
	catch (const json::parse_error& e)
	{
		PIDebug(e.what());
		return input;
	}
	return jRoot.dump(JSON_DUMP_INDENTATION);
}

bool JsonParser::IsStillActiveOfflineToken(const std::string& input)
{
	json jRoot;
	try
	{
		jRoot = json::parse(input);
	}
	catch (const json::parse_error& e)
	{
		PIDebug(e.what());
		return true;
	}

	if (jRoot.contains("result"))
	{
		auto& jResult = jRoot["result"];
		if (jResult.contains("error"))
		{
			auto& jError = jResult["error"];
			if (jError.contains("code"))
			{
				return jError["code"].get<int>() != 905;
			}
		}
	}

	return true;
}

HRESULT ParseOfflineDataItem(json jRoot, OfflineData& data)
{
	// General info independent of token type
	data.refilltoken = GetStringOrEmpty(jRoot, "refilltoken");
	data.username = GetStringOrEmpty(jRoot, "username");

	// Token type specific info
	auto& response = jRoot["response"];
	if (response == nullptr)
	{
		PIDebug("Offline data item did not contain 'response'");
		return PI_JSON_PARSE_ERROR;
	}
	
	const bool isWebAuthn = response.contains("credentialId") && response.contains("rpId") && response.contains("pubKey");
	if (isWebAuthn)
	{
		data.pubKey = GetStringOrEmpty(response, "pubKey");
		data.credId = GetStringOrEmpty(response, "credentialId");
		data.rpId = GetStringOrEmpty(response, "rpId");
	}
	else // HOTP
	{
		for (const auto& item : response.items())
		{
			string key = item.key();
			string value = item.value();
			data.offlineOTPs.try_emplace(key, value);
		}
		// count (max stored otps)
		try
		{
			if (jRoot["count"].is_string())
			{
				try
				{
					data.count = stoi(jRoot["count"].get<std::string>());
				}
				catch (const std::invalid_argument& e)
				{
					PIDebug(e.what());
				}
			}
		}
		catch (const json::type_error& e)
		{
			PIDebug(e.what());

		}
	}

	// Try to get the serial - if the data is coming from the save file, the serial will be set
	data.serial = GetStringOrEmpty(jRoot, "serial");
	return S_OK;
}

HRESULT JsonParser::ParseOfflineDataItemFromString(std::string input, OfflineData& data)
{
	auto j = ParseJson(input);
	return ParseOfflineDataItem(j, data);
}

std::string JsonParser::OfflineDataToString(std::vector<OfflineData> data)
{
	// The data can be empty if a webauthn token has been removed as offline token.
	if (data.empty()) return "";
	json::array_t jArray;

	for (auto& item : data)
	{
		// General information not specific to token type
		json jElement;
		jElement["refilltoken"] = item.refilltoken;
		jElement["serial"] = item.serial;
		jElement["username"] = item.username;

		const bool isWebAuthn = !item.pubKey.empty() && !item.credId.empty() && !item.rpId.empty();
		json jResponse; // token type specific offline data is listed in the "response" object

		if (isWebAuthn)
		{
			jResponse["pubKey"] = item.pubKey;
			jResponse["credentialId"] = item.credId;
			jResponse["rpId"] = item.rpId;
		}
		else // HOTP
		{
			jElement["count"] = to_string(item.offlineOTPs.size());
			for (auto& otpEntry : item.offlineOTPs)
			{
				jResponse[otpEntry.first] = otpEntry.second;
			}
		}

		jElement["response"] = jResponse;
		jArray.push_back(jElement);
	}

	json jRoot;
	jRoot["offline"] = jArray;

	return jRoot.dump(4);
}

std::vector<OfflineData> JsonParser::ParseFileContentsForOfflineData(std::string input)
{
	PIDebug(__FUNCTION__);
	auto j = ParseJson(input);

	std::vector<OfflineData> ret;

	auto& jOffline = j["offline"];

	if (jOffline.is_array())
	{
		for (auto const& item : jOffline)
		{
			OfflineData d;
			ParseOfflineDataItem(item, d);
			ret.push_back(d);
		}
	}
	return ret;
}

std::vector<OfflineData> JsonParser::ParseResponseForOfflineData(std::string serverResponse)
{
	PIDebug(__FUNCTION__);
	std::vector<OfflineData> ret;
	auto jRoot = ParseJson(serverResponse);
	if (jRoot == nullptr) return ret;

	auto& jAuthItems = jRoot["auth_items"];
	if (jAuthItems == nullptr) return ret;

	// Get the serial to add to the data
	string serial = GetStringOrEmpty(jRoot["detail"], "serial");

	auto& jOffline = jAuthItems["offline"];

	if (!jOffline.is_array() || jOffline.size() < 1)
	{
		return ret;
	}

	for (const auto& jItem : jOffline)
	{
		OfflineData newData;
		if (ParseOfflineDataItem(jItem, newData) == S_OK)
		{
			// Add the serial explicitly because it is not part of the 'offline' section of the response, but required for refill later
			newData.serial = serial;
			ret.push_back(newData);
			PIDebug("Received offline data for user '" + newData.username + "'");
		}
	}
	return ret;
}

std::string JsonParser::GetRefilltoken(std::string input)
{
	auto jRoot = ParseJson(input);
	if (jRoot == nullptr) return "";
	try
	{
		json jOffline = jRoot["auth_items"]["offline"].at(0);
		return GetStringOrEmpty(jOffline, "refilltoken");
	}
	catch (const std::exception& e)
	{
		PIError(e.what());
		return "";
	}
}

HRESULT JsonParser::ParseRefillResponse(const std::string& in, const std::string& username, OfflineData& data)
{
	PIDebug(__FUNCTION__);
	auto jRoot = ParseJson(in);
	if (jRoot == nullptr) return PI_JSON_PARSE_ERROR;
	json jOffline;
	try
	{
		jOffline = jRoot["auth_items"]["offline"].at(0);
	}
	catch (const std::exception& e)
	{
		PIDebug(e.what());
		return PI_JSON_PARSE_ERROR;
	}

	if (jOffline == nullptr) return PI_JSON_PARSE_ERROR;

	if (jOffline.contains("response"))
	{
		auto& jResponse = jOffline["response"];
		for (const auto& jItem : jResponse.items())
		{
			string key = jItem.key();
			string value = jItem.value();
			data.offlineOTPs.try_emplace(key, value);
		}
	}
	else
	{
		PIDebug("'Reponse' field missing in OfflineRefill response");
		return E_FAIL;
	}

	if (jOffline.contains("refilltoken"))
	{
		data.refilltoken = GetStringOrEmpty(jOffline, "refilltoken");
	}
	else
	{
		PIDebug("Missing refill token in server response.");
		data.refilltoken = "";
	}
	data.username = username;
	return S_OK;
}

bool JsonParser::ParsePollTransaction(std::string input)
{
	auto jRoot = ParseJson(input);
	if (jRoot == nullptr) return false;

	if (jRoot.contains("result"))
	{
		return GetBoolOrFalse(jRoot["result"], "value");
	}
	else
	{
		PIDebug("PollTransaction response did not contain result");
	}

	return false;
}