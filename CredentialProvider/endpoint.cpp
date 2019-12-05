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
#include "Challenge.h"
#include "Configuration.h"
#include "helper.h"
#include "nlohmann/json.hpp"
#include "../CredentialProvider/core/hooks.h"
#include <winhttp.h>
#include <atlutil.h>
#include <algorithm>
#include <thread>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

#define PRINT_ENDPOINT_RESPONSES

using namespace std;
using json = nlohmann::json;

Endpoint::Endpoint()
{
	auto& config = Configuration::Get();
	this->_customPort = config.endpoint.customPort;
	this->_hostname = config.endpoint.hostname;
	this->_path = config.endpoint.path;
	this->_ignoreInvalidCN = config.endpoint.sslIgnoreCN;
	this->_ignoreUnknownCA = config.endpoint.sslIgnoreCA;
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

Endpoint& Endpoint::operator=(Endpoint const& endpoint)
{
	if (this != &endpoint)
	{
		_ignoreInvalidCN = endpoint._ignoreInvalidCN;
		_ignoreUnknownCA = endpoint._ignoreUnknownCA;
		_customPort = endpoint._customPort;
		_hostname = endpoint._hostname;
		_path = endpoint._path;
		std::lock_guard<std::mutex> guard(_mutex);
		_runPoll = endpoint._runPoll;
	}
	return *this;
}

string Endpoint::connect(string endpoint, map<string, string> params, RequestMethod method)
{
	// Prepare the parameters
	wstring wHostname = get_utf16(Helper::ws2s(_hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = get_utf16((Helper::ws2s(_path) + endpoint), CP_UTF8);

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
		int port = (_customPort != 0) ? _customPort : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), port, 0);
	}
	else
	{
		DbgRelPrintLn("WinHttpOpen failure: " + to_string(GetLastError()));
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
	else
	{
		DbgRelPrintLn("WinHttpSetOption to set TLS flag failure: " + to_string(GetLastError()));
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

	if (!bResults)
	{
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
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
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
	if (!bResults)
	{
		DbgRelPrintLn("WinHttp Result error: " + to_string(GetLastError()));
		response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
	}
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

#ifdef _DEBUG
#ifdef PRINT_ENDPOINT_RESPONSES
	auto j = nlohmann::json::parse(response);
	DebugPrintLn(j.dump(4));
#endif
#endif

	return response;
}

HRESULT Endpoint::parseAuthenticationRequest(string in)
{
	DebugPrintLn(__FUNCTION__);
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
	DebugPrintLn(__FUNCTION__);
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

		////// NEW
		Challenge c(message, txid, serial, type);
		config.challenge_response.challenges.emplace_back(c);

		//////
		if (type == "push")
		{
			config.challenge_response.usingPushToken = true;
			config.challenge_response.tta = (config.challenge_response.tta == TTA::OTP) ? TTA::BOTH : TTA::PUSH;
		}
		else
		{
			config.challenge_response.tta = (config.challenge_response.tta == TTA::PUSH) ? TTA::BOTH : TTA::OTP;
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
	DebugPrintLn(__FUNCTION__);
	// TODO parse any error text and set it to status
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

HRESULT Endpoint::pollForTransactionWithLoop(std::string transaction_id)
{
	DebugPrintLn(__FUNCTION__);
	map<string, string> params;
	params.try_emplace("transaction_id", transaction_id);
	setRunPoll(true);
	HRESULT res = E_FAIL;
	while (_runPoll)
	{
		string response = connect(PI_ENDPOINT_POLL_TX, params, RequestMethod::GET);
		res = parseForTransactionSuccess(response);
		if (res == ENDPOINT_STATUS_AUTH_OK)
		{
			Configuration::Get().endpoint.status = ENDPOINT_STATUS_AUTH_OK;
			setRunPoll(false);
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
	}
	//Hook::CredentialHooks::ResetScenario(Configuration::Get().provider.pCredProvCredential, Configuration::Get().provider.pCredProvCredentialEvents);
	DebugPrintLn("Polling stopped.");

	// if polling is successfull, the authentication has to be finalized
	res = finalizePolling(Helper::ws2s(Configuration::Get().credential.user_name), transaction_id);
	if (res == ENDPOINT_STATUS_AUTH_OK) {
		Configuration::Get().challenge_response.pushAuthenticationSuccessful = true;
		Configuration::Get().provider._pCredentialProviderEvents->CredentialsChanged(Configuration::Get().provider._upAdviseContext);
	}

	return S_OK;
}

HRESULT Endpoint::pollForTransactionSingle(std::string transaction_id)
{
	map<string, string> params;
	params.try_emplace("transaction_id", transaction_id);
	string response = connect(PI_ENDPOINT_POLL_TX, params, RequestMethod::GET);
	return parseForTransactionSuccess(response);
	/*if (res == ENDPOINT_STATUS_AUTH_OK)
	{
		Configuration::Get().endpoint.status = ENDPOINT_STATUS_AUTH_OK;
		return S_OK;
	} */
}

HRESULT Endpoint::parseForTransactionSuccess(std::string in)
{
	DebugPrintLn(__FUNCTION__);
	/*if (in.empty())
	{
		return E_FAIL;
	}
	auto j = json::parse(in);

	auto challenges = j["result"];

	if (challenges.empty())
	{
		return parseForError(in);
	}

	for (auto val : challenges.items())
	{
		auto j2 = val.value();
		const bool success = j2["value"].get<bool>();
		if (success)
		{
			DebugPrintLn("value is true!");
			return ENDPOINT_STATUS_AUTH_OK;
		}
	}
	DebugPrintLn("value is false");
	return ENDPOINT_STATUS_AUTH_FAIL;*/
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

HRESULT Endpoint::finalizePolling(std::string user, std::string transaction_id)
{
	map<string, string> params;
	params.try_emplace("user", user);
	params.try_emplace("transaction_id", transaction_id);
	params.try_emplace("pass", "");

	string response = connect(PI_ENDPOINT_VALIDATE_CHECK, params, RequestMethod::POST);
	return parseAuthenticationRequest(response);
}

void Endpoint::setRunPoll(bool val)
{
	const std::lock_guard<std::mutex> lock(_mutex);
	_runPoll = val;
}