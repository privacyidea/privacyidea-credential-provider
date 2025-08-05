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

#include <regex>
#include "Convert.h"
#include "JsonParser.h"
#include "Logger.h"
#include "nlohmann/json.hpp"
#include "FIDOSignRequest.h"

using json = nlohmann::json;
using namespace std;


void ParseVersionString(const std::string& version, PIResponse& response)
{
	int major = 0, minor = 0, patch = 0;
	std::string suffix;

	// Cut off at the first '+', if present
	std::string mainVersion = version;
	size_t plusPos = version.find('+');
	if (plusPos != std::string::npos)
	{
		mainVersion = version.substr(0, plusPos);
	}

	// Improved regex: matches 3.10, 3.10.dev1, 3.10.2, 3.10.2.beta, 3.10.2dev1, etc.
	std::regex re(R"(^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:[.\-]?([a-zA-Z0-9][a-zA-Z0-9._-]*))?\s*$)");
	std::smatch match;
	if (std::regex_match(mainVersion, match, re))
	{
		major = std::stoi(match[1]);
		minor = std::stoi(match[2]);
		if (match[3].matched)
			patch = std::stoi(match[3]);
		else
			patch = 0;
		if (match[4].matched)
			suffix = match[4];
		else
			suffix.clear();
	}
	response.privacyIDEAVersionMajor = major;
	response.privacyIDEAVersionMinor = minor;
	response.privacyIDEAVersionPatch = patch;
	response.privacyIDEAVersionSuffix = suffix;
}

int GetIntOrZero(json& input, string fieldName)
{
	auto& t = input[fieldName];
	if (t.is_number_integer())
	{
		return t.get<int>();
	}
	else
	{
		//PIDebug(fieldName + " was expected to be int, but was not.");
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
		//PIDebug(fieldName + " was expected to be string, but was not.");
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
		//PIDebug(fieldName + " was expected to be bool, but was not.");
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

		string authStatus = GetStringOrEmpty(jResult, "authentication");
		if (!authStatus.empty())
		{
			if (authStatus == "ACCEPT")
			{
				response.authenticationStatus = AuthenticationStatus::ACCEPT;
			}
			else if (authStatus == "REJECT")
			{
				response.authenticationStatus = AuthenticationStatus::REJECT;
			}
			else if (authStatus == "CHALLENGE")
			{
				response.authenticationStatus = AuthenticationStatus::CHALLENGE;
			}
		}

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

	response.isEnrollCancellable = GetBoolOrFalse(jDetail, "enroll_via_multichallenge_optional");
	response.isEnrollViaMultichallenge = GetBoolOrFalse(jDetail, "enroll_via_multichallenge");

	// Passkey challenge
	auto& passkey = jDetail["passkey"];
	if (!passkey.empty())
	{
		response.passkeyChallenge = FIDOSignRequest(
			GetStringOrEmpty(passkey, "challenge"),
			GetStringOrEmpty(passkey, "rpId"),
			GetStringOrEmpty(passkey, "user_verification"),
			GetStringOrEmpty(passkey, "transaction_id"),
			GetStringOrEmpty(passkey, "message"),
			"passkey");
	}

	response.message = GetStringOrEmpty(jDetail, "message");

	auto username = GetStringOrEmpty(jDetail, "username");
	if (!username.empty())
	{
		response.username = username;
	}

	// Multi-challenge
	auto& multiChallenge = jDetail["multi_challenge"];
	if (!multiChallenge.empty())
	{
		response.transactionId = GetStringOrEmpty(jDetail, "transaction_id");
		response.preferredMode = GetStringOrEmpty(jDetail, "preferred_client_mode");

		for (auto& challenge : multiChallenge.items())
		{
			json jChallenge = challenge.value();
			if (jChallenge.contains("passkey_registration"))
			{
				auto& pkreg = jChallenge["passkey_registration"];
				auto& rp = pkreg["rp"];

				auto registrationRequest = FIDORegistrationRequest();
				registrationRequest.rpId = GetStringOrEmpty(rp, "id");
				registrationRequest.rpName = GetStringOrEmpty(rp, "name");
				auto& user = pkreg["user"];
				registrationRequest.userName = GetStringOrEmpty(user, "name");
				registrationRequest.userDisplayName = GetStringOrEmpty(user, "displayName");
				registrationRequest.userId = GetStringOrEmpty(user, "id");

				registrationRequest.challenge = GetStringOrEmpty(pkreg, "challenge");
				registrationRequest.transactionId = GetStringOrEmpty(jChallenge, "transaction_id");
				registrationRequest.serial = GetStringOrEmpty(jChallenge, "serial");
				registrationRequest.type = "passkey";
				auto& authenticatorSelection = pkreg["authenticatorSelection"];
				if (authenticatorSelection.is_object())
				{
					for (auto& item : authenticatorSelection.items())
					{
						string key = item.key();
						json value = item.value();
						if (key == "residentKey")
						{
							registrationRequest.residentKey = value.get<std::string>() == "required";
						}
						else if (key == "userVerification")
						{
							registrationRequest.userVerification = value.get<std::string>() == "required";
						}
						else if (key == "requireResidentKey")
						{
							registrationRequest.residentKey = value.get<bool>();
						}
					}
				}
				else
				{
					PIDebug("authenticatorSelection in passkey_registration was expected to be object, but was not.");
				}
				// PubKeyCredParams				
				auto& pubKeyCredParams = pkreg["pubKeyCredParams"];
				if (pubKeyCredParams.is_array())
				{
					for (const auto& item : pubKeyCredParams)
					{
						if (item.is_object())
						{
							std::string type = item.at("type").get<std::string>();
							int alg = item.at("alg").get<int>();
							registrationRequest.pubKeyCredParams.emplace_back(type, alg);
						}
						else
						{
							PIDebug("Warning: Found non-object element in pubKeyCredParams array.");
						}
					}
				}
				else
				{
					PIDebug("pubKeyCredParams in passkey_registration was expected to be array, but was not.");
				}

				response.passkeyRegistration = registrationRequest;
			}
			else
			{
				// Standard challenge
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
					FIDOSignRequest signRequest;
					signRequest.challenge = GetStringOrEmpty(jSignRequest, "challenge");
					signRequest.rpId = GetStringOrEmpty(jSignRequest, "rpId");
					signRequest.userVerification = GetStringOrEmpty(jSignRequest, "userVerification");
					signRequest.timeout = GetIntOrZero(jSignRequest, "timeout");
					signRequest.allowCredentials = allowCredentials;
					signRequest.type = "webauthn";
					c.fidoSignRequest = signRequest;
				}
				else if (type == "passkey")
				{
					FIDOSignRequest signRequest;
					signRequest.challenge = GetStringOrEmpty(jChallenge, "challenge");
					signRequest.userVerification = GetStringOrEmpty(jChallenge, "userVerification");
					signRequest.rpId = GetStringOrEmpty(jChallenge, "rpId");
					c.fidoSignRequest = signRequest;
				}
				response.challenges.push_back(c);
			}
		}
	}

	// Version
	if (jRoot.contains("versionnumber")) 
	{
		ParseVersionString(jRoot["versionnumber"].get<std::string>(), response);
		PIDebug("Parsed version: " + 
			std::to_string(response.privacyIDEAVersionMajor) + "." +
			std::to_string(response.privacyIDEAVersionMinor) + "." +
			std::to_string(response.privacyIDEAVersionPatch) + response.privacyIDEAVersionSuffix);
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
		data.userId = GetStringOrEmpty(response, "userId");
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
			jResponse["userId"] = item.userId;
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
			if (newData.serial.empty())
			{
				// Add the serial explicitly if it is not part of the 'offline' section of the response,
				// but a serial is required for refill later
				newData.serial = serial;
			}

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