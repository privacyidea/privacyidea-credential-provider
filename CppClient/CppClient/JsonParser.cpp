#include "JsonParser.h"
#include "../nlohmann/json.hpp"
#include "Logger.h"

using json = nlohmann::json;
using namespace std;

string GetStringOrEmpty(json& input, string fieldName)
{
	auto& t = input[fieldName];
	if (t.is_string())
	{
		return t.get<string>();
	}
	else
	{
		DebugPrint(fieldName + " was expected to be string, but was not.");
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
		DebugPrint(fieldName + " was expected to be bool, but was not.");
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
		DebugPrint(e.what());
		return nullptr;
	}
	return jRoot;
}

HRESULT JsonParser::ParsePIResponse(std::string serverResponse, PIResponse& responseObj)
{
	DebugPrint(__FUNCTION__);
	json jRoot;
	try
	{
		jRoot = json::parse(serverResponse);
	}
	catch (const json::parse_error& e)
	{
		DebugPrint(e.what());
		return PI_JSON_PARSE_ERROR;
	}

	if (jRoot.contains("result"))
	{
		auto& jResult = jRoot["result"];

		responseObj.value = GetBoolOrFalse(jResult, "value");
		responseObj.status = GetBoolOrFalse(jResult, "status");

		if (jResult.contains("error"))
		{
			auto& jError = jResult["error"];
			responseObj.errorCode = jError["code"].get<int>();
			responseObj.errorMessage = GetStringOrEmpty(jError, "message");
		}
	}
	else
	{
		DebugPrint("Reponse did not contain 'result'");
		return PI_JSON_PARSE_ERROR;
	}


	auto& jDetail = jRoot["detail"];

	responseObj.message = GetStringOrEmpty(jDetail, "message");
	
	auto& multiChallenge = jDetail["multi_challenge"];
	if (!multiChallenge.empty())
	{
		responseObj.transactionId = GetStringOrEmpty(jDetail, "transaction_id");
		for (auto& item : multiChallenge.items())
		{
			Challenge c;
			json jChallenge = item.value();

			c.type = GetStringOrEmpty(jChallenge, "type");
			c.message = GetStringOrEmpty(jChallenge, "message");
			c.serial = GetStringOrEmpty(jChallenge, "serial");
			c.transaction_id = GetStringOrEmpty(jChallenge, "transaction_id");

			responseObj.challenges.push_back(c);
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
		DebugPrint(e.what());
		return input;
	}
	return jRoot.dump(JSON_DUMP_INDENTATION);
}

HRESULT ParseOfflineDataItem(json jRoot, OfflineData& data)
{
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
				DebugPrint(e.what());
			}
		}
	}
	catch (const json::type_error& e)
	{
		DebugPrint(e.what());
	}

	data.refilltoken = GetStringOrEmpty(jRoot, "refilltoken");
	data.username = GetStringOrEmpty(jRoot, "username");

	auto &jOTPs = jRoot["response"];
	if (jOTPs != nullptr)
	{
		for (const auto& item : jOTPs.items())
		{
			string key = item.key();
			string value = item.value();
			data.offlineOTPs.try_emplace(key, value);
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
	json::array_t jArray;

	for (auto& item : data)
	{
		json jElement;
		jElement["count"] = to_string(item.GetOfflineOTPCount());
		jElement["refilltoken"] = item.refilltoken;
		jElement["serial"] = item.serial;
		jElement["username"] = item.username;

		json jResponse;

		for (auto& otpEntry : item.offlineOTPs)
		{
			jResponse[otpEntry.first] = otpEntry.second;
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
	DebugPrint(__FUNCTION__);
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
	DebugPrint(__FUNCTION__);
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
			DebugPrint("Received offline data for user '" + newData.username + "'");
		}
	}
	return ret;
}

HRESULT JsonParser::ParseRefillResponse(const std::string& in, const std::string& username, OfflineData& data)
{
	DebugPrint(__FUNCTION__);
	auto jRoot = ParseJson(in);
	if (jRoot == nullptr) return PI_JSON_PARSE_ERROR;
	json jOffline;
	try
	{
		jOffline = jRoot["auth_items"]["offline"].at(0);
	}
	catch (const std::exception& e)
	{
		DebugPrint(e.what());
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
		DebugPrint("'Reponse' field missing in OfflineRefill response");
		return E_FAIL;
	}

	if (jOffline.contains("refilltoken"))
	{
		data.refilltoken = GetStringOrEmpty(jOffline, "refilltoken");
	}
	else
	{
		DebugPrint("Missing refill token in server response.");
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
		DebugPrint("PollTransaction response did not contain result");
	}

	return false;
}