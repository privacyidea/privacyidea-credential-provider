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

#include "PrivacyIDEA.h"
#include "Endpoint.h"
#include "Logger.h"
#include "Challenge.h"
#include "../nlohmann/json.hpp"

#include <winhttp.h>
#include <atlutil.h>

#pragma comment(lib, "winhttp.lib")

#define PRINT_ENDPOINT_RESPONSES

using namespace std;
using json = nlohmann::json;

vector<std::string> _excludedEndpoints = { PI_ENDPOINT_POLL_TX };

string Endpoint::escapeUrl(const string& in)
{
	if (in.empty())
	{
		return in;
	}
	DWORD len = in.size();
	const DWORD maxLen = (len * 3);
	DWORD* pdwLen = nullptr;
	LPSTR buf = (char*)malloc(sizeof(char) * maxLen);
	if (buf == nullptr)
	{
		DebugPrint("malloc fail");
		return "";
	}
	LPCSTR input = in.c_str();
	BOOL res = AtlEscapeUrl(input, buf, pdwLen, maxLen, (DWORD)NULL);

	if (res)
	{
		string ret(buf);
		free(buf);
		return ret;
	}
	else
	{
		DebugPrint("AtlEscapeUrl Failure");
		free(buf);
		return "";
	}
}

const std::string& Endpoint::getLastErrorMessage()
{
	return _lastErrorMessage;
}

nlohmann::json Endpoint::tryParseJSON(const std::string& in)
{
	json j;
	try
	{
		j = json::parse(in);
		return j;
	}
	catch (const json::parse_error & e)
	{
		DebugPrint(e.what());
		return nullptr;
	}
}

wstring Endpoint::get_utf16(const std::string& str, int codepage)
{
	if (str.empty()) return wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], str.size(), 0, 0);
	wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], str.size(), &res[0], sz);
	return res;
}

string Endpoint::connect(const string& endpoint, map<string, string> params, const RequestMethod& method)
{
	// Prepare the parameters
	wstring wHostname = get_utf16(PrivacyIDEA::ws2s(_hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = get_utf16((PrivacyIDEA::ws2s(_path) + endpoint), CP_UTF8);

	// Encode and accumulate the data
	string toSend;
	for (auto const& x : params)
	{
		toSend += escapeUrl(x.first) + "=" + escapeUrl(x.second) + "&";
	}
	toSend = toSend.substr(0, (toSend.length() - 1));
	DebugPrint("Params: " + toSend);
	LPSTR data = _strdup(toSend.c_str());
	const DWORD data_len = strnlen_s(toSend.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

#ifdef _DEBUG
	wstring msg = L"Sending to: " + wHostname + fullPath;
	DebugPrint(msg.c_str());
	if (_logPasswords)
	{
		DebugPrint("data:");
		DebugPrint(data);			// !!! this can log the windows password in cleartext !!!
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
		int port = (_customPort != 0) ? _customPort : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), port, 0);
	}
	else
	{
		ReleaseDebugPrint("WinHttpOpen failure: " + to_string(GetLastError()));
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}
	// Create an HTTPS request handle. SSL indicated by WINHTTP_FLAG_SECURE
	if (hConnect)
	{
		hRequest = WinHttpOpenRequest(hConnect, requestMethod, fullPath.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	}
	else
	{
		ReleaseDebugPrint("WinHttpOpenRequest failure: " + to_string(GetLastError()));
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
	else
	{
		ReleaseDebugPrint("WinHttpSetOption to set TLS flag failure: " + to_string(GetLastError()));
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}

	/////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
	DWORD dwSSLFlags = 0;
	if (_ignoreUnknownCA) {
		dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		//DebugPrintLn("SSL ignore unknown CA flag set");
	}

	if (_ignoreInvalidCN) {
		dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		//DebugPrintLn("SSL ignore invalid CN flag set");
	}

	if (_ignoreUnknownCA || _ignoreInvalidCN) {
		if (WinHttpSetOption(hRequest,
			WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD))) {
			//DebugPrintLn("WinHttpOption flags set to ignore SSL errors");
		}
		else
		{
			ReleaseDebugPrint("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
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

	if (!bResults)
	{
		ReleaseDebugPrint("WinHttpSendRequest failure: " + to_string(GetLastError()));
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
				ReleaseDebugPrint("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
				response = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				ReleaseDebugPrint("WinHttpReadData out of memory: " + to_string(GetLastError()));
				response = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
					ReleaseDebugPrint("WinHttpReadData error: " + to_string(GetLastError()));
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
	if (!bResults)
	{
		ReleaseDebugPrint("WinHttp Result error: " + to_string(GetLastError()));
		response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
	}
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

#ifdef _DEBUG
	if (std::find(_excludedEndpoints.begin(), _excludedEndpoints.end(), endpoint) == _excludedEndpoints.end())
	{
		auto j = nlohmann::json::parse(response);
		DebugPrint(j.dump(4));
	}
#endif

	return response;
}

HRESULT Endpoint::parseAuthenticationRequest(const string& in)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	//string value = j["result"]["value"].get<std::string>();
	string value = j["result"]["value"].dump();
	if (value == "null")
	{
		return parseForError(in);
	}
	else
	{
		return (value == "true") ? PI_AUTH_SUCCESS : PI_AUTH_FAILURE;
	}
	return PI_AUTH_FAILURE;
}

HRESULT Endpoint::parseTriggerRequest(const std::string& in, Challenge& c)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	json multiChallenge = j["detail"]["multi_challenge"];

	if (multiChallenge.empty())
	{
		return PI_NO_CHALLENGES;
	}

	// Check each element for messages / transaction IDs / push token
	for (auto val : multiChallenge.items())
	{
		json j2 = val.value();
		string message = j2["message"].get<std::string>();
		string type = j2["type"].get<std::string>();
		string txid = j2["transaction_id"].get<std::string>();
		string serial = j2["serial"].get<std::string>();

		if (!type.empty()) {

			if (type == "push")
			{
				c.tta = (c.tta == TTA::OTP) ? TTA::BOTH : TTA::PUSH;
			}
			else
			{
				c.tta = (c.tta == TTA::PUSH) ? TTA::BOTH : TTA::OTP;
			}
		}
		// TODO currently stores the first set of data, need more?
		if (!message.empty())
		{
			// TODO Accumulate if there are multiple message, no duplicates
			c.addMessage(message);
		}
		if (!txid.empty())
		{
			c.transaction_id = txid;
		}
		if (!serial.empty())
		{
			c.serial = serial;
		}
	}
	return PI_TRIGGERED_CHALLENGE;
}

HRESULT Endpoint::parseForError(const std::string& in)
{
	DebugPrint(__FUNCTION__);
	// TODO parse any error text and set it to status
	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	// Check for error code and message
	/*auto error = j["result"]["error"];
	if (error.is_object())
	{
		auto jErrCode = error["code"];
		auto jErrMsg = error["message"];

		if (jErrCode.is_number())
		{

		}
	} */

	string errorCode = j["result"]["error"]["code"].dump();
	string errorMessage = j["result"]["error"]["message"].dump();

	if (errorCode == "null" && errorMessage == "null")
	{
		ReleaseDebugPrint("Received unknown reponse from server:" + in);
		return E_INVALIDARG;
	}

	if (errorCode != "null")
		_lastErrorCode = std::stoi(errorCode);

	if (errorMessage != "null")
		_lastErrorMessage = errorMessage;

	return PI_JSON_ERROR_CONTAINED;
}

const int& Endpoint::getLastErrorCode()
{
	return _lastErrorCode;
}

HRESULT Endpoint::pollForTransaction(const std::map<std::string, std::string>& params)
{
	string response = connect(PI_ENDPOINT_POLL_TX, params, RequestMethod::GET);
	return parseForTransactionSuccess(response);
}

HRESULT Endpoint::parseForTransactionSuccess(const std::string& in)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	//string value = j["result"]["value"].get<std::string>();
	string value = j["result"]["value"].dump();
	if (value.empty())
	{
		return parseForError(in);
	}
	else
	{
		return (value == "true") ? PI_TRANSACTION_SUCCESS : PI_TRANSACTION_FAILURE;
	}
	return PI_TRANSACTION_FAILURE;
}

HRESULT Endpoint::finalizePolling(const std::string& user, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	map<string, string> params;
	params.try_emplace("user", user);
	params.try_emplace("transaction_id", transaction_id);
	params.try_emplace("pass", "");

	string response = connect(PI_ENDPOINT_VALIDATE_CHECK, params, RequestMethod::POST);
	return parseAuthenticationRequest(response);
}