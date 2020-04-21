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

SecureString Endpoint::escapeUrl(const std::string& in)
{
	return escapeUrl(SecureString(in.c_str())).c_str();
}

SecureString Endpoint::escapeUrl(const SecureString& in)
{
	if (in.empty())
	{
		return in;
	}
	const DWORD maxLen = (in.size() * 3);
	DWORD* pdwWritten = nullptr;
	LPSTR buf = (char*)malloc(sizeof(char) * maxLen);
	if (buf == nullptr)
	{
		DebugPrint("malloc fail");
		return "";
	}
	SecureString ret;

	if (AtlEscapeUrl(in.c_str(), buf, pdwWritten, maxLen, (DWORD)NULL))
		ret = SecureString(buf);
	else
		DebugPrint("AtlEscapeUrl Failure");

	SecureZeroMemory(buf, (sizeof(char) * maxLen));
	free(buf);
	return ret;
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
	catch (const json::parse_error& e)
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

string Endpoint::connect(const string& endpoint, SecureString sdata, const RequestMethod& method)
{
	// Prepare the parameters
	wstring wHostname = get_utf16(PrivacyIDEA::ws2s(_hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = get_utf16((PrivacyIDEA::ws2s(_path) + endpoint), CP_UTF8);

	LPSTR data = _strdup(sdata.c_str());
	const DWORD data_len = strnlen_s(sdata.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

#ifdef _DEBUG
	if (endpoint != PI_ENDPOINT_POLL_TX)
	{
		DebugPrint(L"Sending to: " + wHostname + fullPath);
		if (_logPasswords)
		{
			DebugPrint("data: " + SecureString(data));
		}
		// !!! this can log the windows password in cleartext !!!
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
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Set timeouts in ms
	//WinHttpSetTimeouts(hSession, 2000, 2000, 2000, 10000);

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
		_lastErrorCode = GetLastError();
		_lastErrorMessage = "Server unreachable!";
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
			pszOutBuffer = new char[ULONGLONG(dwSize) + 1];
			if (!pszOutBuffer)
			{
				ReleaseDebugPrint("WinHttpReadData out of memory: " + to_string(GetLastError()));
				response = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, (ULONGLONG)dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
					ReleaseDebugPrint("WinHttpReadData error: " + to_string(GetLastError()));
					response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
				}
				else
				{
					response = response + string(pszOutBuffer);
				}
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

	SecureZeroMemory(data, data_len);

#ifdef _DEBUG
	if (std::find(_excludedEndpoints.begin(), _excludedEndpoints.end(), endpoint) == _excludedEndpoints.end())
	{
		if (!response.empty()) {
			try {
				auto j = nlohmann::json::parse(response);
				DebugPrint(j.dump(4));
			}
			catch (json::exception& e) {
				DebugPrint("JSON parse exception: " + string(e.what()) + ", response was: " + response);
			}
		}
		else
			DebugPrint("Response was empty.");
	}
#endif

	if (response.empty())
	{
		_lastErrorMessage = "Server unreachable!";
	}

	return response;
}

SecureString Endpoint::encodePair(const std::string& key, const std::string& value)
{
	return SecureString(key.c_str()) + "=" + escapeUrl(value);
}

SecureString Endpoint::encodePair(const std::string& key, const SecureString& value)
{
	return SecureString(key.c_str()) + "=" + escapeUrl(value);
}

SecureString Endpoint::encodePair(const std::string& key, const SecureWString& value)
{
	return encodePair(key, PrivacyIDEA::sws2ss(value));
}

HRESULT Endpoint::parseAuthenticationRequest(const string& in)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	auto jValue = j["result"]["value"];
	if (jValue.is_null())
	{
		return parseForError(in);
	}
	else
	{
		if (jValue.is_boolean())
		{
			return (jValue.get<boolean>() ? PI_AUTH_SUCCESS : PI_AUTH_FAILURE);
		}
		return PI_AUTH_FAILURE;
	}
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

	// Get the message from detail, that is the accumulated message created by privacyIDEA
	auto jMessage = j["detail"]["message"];
	if (jMessage.is_string())
		c.message = PrivacyIDEA::s2ws(jMessage.get<std::string>());

	// Check each element for transaction IDs / push token
	for (auto val : multiChallenge.items())
	{
		json j2 = val.value();
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
	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	// Check for error code and message
	auto error = j["result"]["error"];
	if (error.is_object())
	{
		auto jErrCode = error["code"];
		auto jErrMsg = error["message"];

		if (jErrCode.is_number() && jErrMsg.is_string())
		{
			_lastErrorCode = jErrCode.get<int>();
			_lastErrorMessage = jErrMsg.get<std::string>();
			return PI_JSON_ERROR_CONTAINED;
		}
	}
	else
	{
		ReleaseDebugPrint("Received unknown reponse from server:" + in);
	}
	return E_INVALIDARG;
}

const int& Endpoint::getLastErrorCode()
{
	return _lastErrorCode;
}

HRESULT Endpoint::pollForTransaction(const SecureString& data)
{
	string response = connect(PI_ENDPOINT_POLL_TX, data, RequestMethod::GET);
	return parseForTransactionSuccess(response);
}

HRESULT Endpoint::parseForTransactionSuccess(const std::string& in)
{
	//DebugPrint(__FUNCTION__);

	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	auto jValue = j["result"]["value"];
	if (!jValue.is_boolean())
	{
		return parseForError(in);
	}

	return jValue.get<bool>() ? PI_TRANSACTION_SUCCESS : PI_TRANSACTION_FAILURE;
}

HRESULT Endpoint::finalizePolling(const std::string& user, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	// Finalize with empty pass
	SecureString data = encodePair("user", user) + "&" + encodePair("transaction_id", transaction_id) + "&pass=";
	string response = connect(PI_ENDPOINT_VALIDATE_CHECK, data, RequestMethod::POST);
	return parseAuthenticationRequest(response);
}