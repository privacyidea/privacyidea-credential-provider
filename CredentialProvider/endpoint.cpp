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

#include "Endpoint.h"
#include "Logger.h"
#include "Configuration.h"
#include "helper.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "nlohmann/json.hpp"
#include <winhttp.h>
#include <atlutil.h>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

using namespace std;
using json = nlohmann::json;

Endpoint::Endpoint()
{
	auto& config = Configuration::Get();
	this->customPort = config.endpoint.customPort;
	this->hostname = config.endpoint.hostname;
	this->path = config.endpoint.path;
	this->ignoreInvalidCN = config.endpoint.sslIgnoreCN;
	this->ignoreUnknownCA = config.endpoint.sslIgnoreCA;
}

string Endpoint::escapeUrl(const string& in)
{
	if (in.empty())
	{
		return in;
	}
	DWORD len = in.size();
	DWORD maxLen = (len * 3);
	DWORD* pdwLen = &len;
	LPSTR out = (char*)malloc(sizeof(char) * maxLen);
	LPCSTR input = in.c_str();
	HRESULT res = AtlEscapeUrl(input, out, pdwLen, maxLen, (DWORD)NULL);

	if (SUCCEEDED(res))
	{
		string ret(out);
		free(out);
		return ret;
	}
	else
	{
		DebugPrintLn("AtlEscapeUrl Failure");
		free(out);
		return "";
	}
}

wstring Endpoint::get_utf16(const std::string& str, int codepage)
{
	if (str.empty()) return wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

string Endpoint::connect(string endpoint, map<string, string> params, RequestMethod method)
{
	// Prepare the parameters
	wstring wHostname = get_utf16(Helper::ws2s(hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = get_utf16((Helper::ws2s(path) + endpoint), CP_UTF8);

	// Encode and accumulate the data
	string toSend;
	for (auto const& x : params)
	{
		toSend += escapeUrl(x.first) + "=" + escapeUrl(x.second) + "&";
	}
	toSend = toSend.substr(0, (toSend.length() - 1));
	DebugPrintLn("String to send: " + toSend);
	LPSTR data = _strdup(toSend.c_str());
	const DWORD data_len = strnlen_s(toSend.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

#ifdef _DEBUG
	wstring msg = L"Sending to: " + wHostname + fullPath;
	DebugPrintLn(msg.c_str());
	if (Configuration::Get().logSensitive)
	{
		DebugPrintLn("data:");
		DebugPrintLn(data);			// !!! this can show the windows password in cleartext !!!
	}
#endif
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = nullptr;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = nullptr,
		hConnect = nullptr,
		hRequest = nullptr;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"privacyidea-cp",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
	{
		int port = (customPort != 0) ? customPort : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), port, 0);
	}
	else
	{
		DbgRelPrintLn("WinHttpOpen failure: " + to_string(GetLastError()));
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}
	// Create an HTTPS request handle. SSL indicated by WINHTTP_FLAG_SECURE
	if (hConnect) {
		hRequest = WinHttpOpenRequest(hConnect, requestMethod, fullPath.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	}
	else {
		DbgRelPrintLn("WinHttpOpenRequest failure: " + to_string(GetLastError()));
		return "";
	}

	// Set Option Security Flags to start TLS
	DWORD dwReqOpts = 0;
	if (WinHttpSetOption(
		hRequest,
		WINHTTP_OPTION_SECURITY_FLAGS,
		&dwReqOpts,
		sizeof(DWORD))) {
	}
	else {
		DbgRelPrintLn("WinHttpSetOption to set TLS flag failure: " + to_string(GetLastError()));
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}

	/////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
	DWORD dwSSLFlags = 0;
	if (ignoreUnknownCA) {
		dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		DebugPrintLn("SSL ignore unknown CA flag set");
	}

	if (ignoreInvalidCN) {
		dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		DebugPrintLn("SSL ignore invalid CN flag set");
	}

	if (ignoreUnknownCA || ignoreInvalidCN) {
		if (WinHttpSetOption(hRequest,
			WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD))) {
			//DebugPrintLn("WinHttpOption flags set to ignore SSL errors");
		}
		else {
			DbgRelPrintLn("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
			return ""; //ENDPOINT_ERROR_SETUP_ERROR;
		}
	}
	///////////////////////////////////////////////////////////////////////////////

	// Define for POST to be recognized
	LPCWSTR additionalHeaders = L"Content-Type: application/x-www-form-urlencoded\r\n";

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			additionalHeaders, (DWORD)-1,
			(LPVOID)data, data_len,
			data_len, 0);

	if (!bResults) {
		DbgRelPrintLn("WinHttpSendRequest failure: " + to_string(GetLastError()));
		return ""; //ENDPOINT_ERROR_CONNECT_ERROR;
	}

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	string response;
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				DbgRelPrintLn("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
				response = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				DbgRelPrintLn("WinHttpReadData out of memory: " + to_string(GetLastError()));
				response = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
					DbgRelPrintLn("WinHttpReadData error: " + to_string(GetLastError()));
					response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
				}
				else
					response = response + string(pszOutBuffer);
				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);
	}
	// Report any errors.
	if (!bResults) {
		DbgRelPrintLn("WinHttp Result error: " + to_string(GetLastError()));
		response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
	}
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return response;
}

/*
HRESULT Endpoint::parseResponse(string json)
{
	DebugPrintLn(__FUNCTION__);

	DebugPrintLn("Plain JSON response:");
	DebugPrintLn(json);

	HRESULT result = E_FAIL;

	if (json.empty())
	{
		DbgRelPrintLn("Server response was empty");
		return ENDPOINT_ERROR_JSON_NULL;
	}

	// 1. Parse a JSON string into DOM.
	rapidjson::Document json_document;
	json_document.Parse(json.c_str());


	if (json_document.HasParseError())
	{
		DbgRelPrintLn("Parse error in response: " + json);
		DebugPrintLn("at: " + to_string(static_cast<unsigned int>(json_document.GetErrorOffset())) + "description: " + string(GetParseError_En(json_document.GetParseError())));
		return ENDPOINT_ERROR_PARSE_ERROR;
	}

	// 1.2 Check detail for serial and transaction id
	if (!json_document.HasMember("detail"))
	{
		DebugPrintLn("JSON reponse has no member detail");
	}
	else
	{
		rapidjson::Value& json_detail = json_document["detail"];
		if (json_detail.IsNull())
		{
			DebugPrintLn("JSON response detail is null");
		}
		else
		{
			if (json_detail.HasMember("serial"))
			{
				rapidjson::Value::MemberIterator json_serial = json_detail.FindMember("serial");
				Configuration::Get().challenge_response.serial = string(json_serial->value.GetString());
				DebugPrintLn("CR serial: " + Configuration::Get().challenge_response.serial);
			}
			else
			{
				DebugPrintLn("JSON response has no serial in detail");
			}

			if (json_detail.HasMember("transaction_id"))
			{
				rapidjson::Value::MemberIterator json_tx_id = json_detail.FindMember("transaction_id");
				Configuration::Get().challenge_response.transactionID = string(json_tx_id->value.GetString());
				DebugPrintLn("CR txID: " + Configuration::Get().challenge_response.transactionID);
			}
			else
			{
				DebugPrintLn("JSON response has no txID in detail");
			}

			// Get the message to display it to the user, limited to 256 bytes at the moment
			if (json_detail.HasMember("message"))
			{
				rapidjson::Value::MemberIterator json_message = json_detail.FindMember("message");
				Configuration::Get().challenge_response.message = string(json_message->value.GetString());
				DebugPrintLn("CR message: " + Configuration::Get().challenge_response.message);
			}
			else
			{
				DebugPrintLn("JSON response has no message in detail");
			}
		}
	}

	// 2. Get result-object
	if (!json_document.HasMember("result"))
	{
		DbgRelPrintLn("Server reponse has no member result: " + json);
		return ENDPOINT_ERROR_NO_RESULT;
	}

	rapidjson::Value& json_result = json_document["result"];

	// 3. Check result
	const rapidjson::Value::MemberIterator json_status = json_result.FindMember("status");
	if (json_status != json_result.MemberEnd() && json_status->value.GetBool()) // request handled successfully?
	{
		result = ENDPOINT_SUCCESS_STATUS_TRUE;

		const rapidjson::Value::MemberIterator json_value = json_result.FindMember("value");
		if (json_value != json_result.MemberEnd() && json_value->value.GetBool()) // authentication successfully?
		{
			result = ENDPOINT_SUCCESS_VALUE_TRUE;
		}
		else
		{
			// No Member "value" or "value" = false
			// This is also reached in case of sending the username and pw to privacyideaIDEA (two step)
			if (!Configuration::Get().twoStepSendPassword)
			{
				DbgRelPrintLn("Server response has no member 'value': " + json);
			}
			result = ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER;
		}
	}
	else
	{
		// No Member "status" or "status" = false
		result = ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;

		// Check if error is present
		if (!json_result.HasMember("error"))
		{
			DbgRelPrintLn("Unknown error in server response: " + json);
			return ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;
		}

		// Check for error code
		rapidjson::Value& json_error = json_result["error"];
		const rapidjson::Value::MemberIterator json_error_code = json_error.FindMember("code");

		if (json_error_code->value.GetInt() == ENDPOINT_RESPONSE_INSUFFICIENT_SUBSCR)
		{
			DbgRelPrintLn("Insufficient subscription");
			result = ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION;
		}
	}
	return result;
}
*/

HRESULT Endpoint::parseAuthenticationRequest(string in)
{
	if (in.empty())
	{
		DbgRelPrintLn("Received empty response from server.");
		return ENDPOINT_ERROR_EMPTY_RESPONSE;
	}

	auto j = json::parse(in);

	//string value = j["result"]["value"].get<std::string>();
	string value = j["result"]["value"].dump();
	if (value.empty())
	{
		return parseForError(in);
	}
	else
	{
		return (value == "true") ? ENDPOINT_STATUS_AUTH_OK : ENDPOINT_STATUS_AUTH_FAIL;
	}
	return ENDPOINT_STATUS_AUTH_FAIL;
}

HRESULT Endpoint::parseTriggerRequest(std::string in)
{
	if (in.empty())
	{
		DbgRelPrintLn("Received empty response from server.");
		return ENDPOINT_ERROR_EMPTY_RESPONSE;
	}
	auto& config = Configuration::Get();
	auto j = json::parse(in);
	json multiChallenge = j["detail"]["multi_challenge"];

	if (multiChallenge.empty())
	{
		return parseForError(in);
	}

	// Check each element for messages / transaction IDs / push token
	for (auto val : multiChallenge.items())
	{
		json j2 = val.value();
		string message = j2["message"].get<std::string>();
		string type = j2["type"].get<std::string>();
		string txid = j2["transaction_id"].get<std::string>();
		string serial = j2["serial"].get<std::string>();
		
		if (type == "push")
		{
			config.challenge_response.usingPushToken = true;
		}

		if (!message.empty())
		{
			// TODO Accumulate if there are multiple message, no duplicates
			config.challenge_response.message = message;
		}
		// TODO are multiple transaction ids possible?
		if (!txid.empty())
		{
			config.challenge_response.transactionID = txid;
		}
		if (!serial.empty())
		{
			config.challenge_response.serial = serial;
		}
		//DebugPrintLn("msg=" + message + ", type=" + type + ", txid=" + txid + ", serial= " + serial);
	}
	// TODO 
	return ENDPOINT_STATUS_AUTH_CONTINUE;
}

HRESULT Endpoint::parseForError(std::string in)
{
	auto j = json::parse(in);
	// Check for error code
	string errorCode = j["result"]["error"]["code"].dump();
	if (errorCode == "101")
	{
		return ENDPOINT_RESPONSE_INSUFFICIENT_SUBSCR;
	}
	else
	{
		DbgRelPrintLn("Received invalid reponse from server:" + in);
		return ENDPOINT_ERROR_RESPONSE_ERROR;
	}
}
