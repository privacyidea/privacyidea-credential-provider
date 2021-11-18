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

Endpoint::Endpoint(PICONFIG conf)
{
	_hostname = conf.hostname;
	_path = conf.path;
	_customPort = conf.customPort;
	_logPasswords = conf.logPasswords;
	_ignoreInvalidCN = conf.ignoreInvalidCN;
	_ignoreUnknownCA = conf.ignoreUnknownCA;

	_resolveTimeout = conf.resolveTimeoutMS; // 0 (not set) is valid and the default
	// If timeout values are set use them, otherwise keep the default
	_connectTimeout = conf.connectTimeoutMS == 0 ? _connectTimeout : conf.connectTimeoutMS;
	_sendTimeout = conf.sendTimeoutMS == 0 ? _sendTimeout : conf.sendTimeoutMS;
	_receiveTimeout = conf.receiveTimeoutMS == 0 ? _receiveTimeout : conf.receiveTimeoutMS;
}

std::string Endpoint::EscapeUrl(const std::string& in)
{
	if (in.empty())
	{
		return in;
	}
	const size_t maxLen = (in.size() * 3);
	DWORD* pdwWritten = nullptr;
	LPSTR buf = (char*)malloc(sizeof(char) * maxLen);
	if (buf == nullptr)
	{
		DebugPrint("malloc fail");
		return "";
	}
	std::string ret;

	if (AtlEscapeUrl(in.c_str(), buf, pdwWritten, (DWORD)maxLen, (DWORD)NULL))
	{
		ret = std::string(buf);
	}
	else
	{
		Print("AtlEscapeUrl Failure");
	}

	SecureZeroMemory(buf, (sizeof(char) * maxLen));
	free(buf);
	return ret;
}

nlohmann::json Endpoint::TryParseJSON(const std::string& in)
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

wstring Endpoint::Get_utf16(const std::string& str, int codepage)
{
	if (str.empty()) return wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

void CALLBACK WinHttpStatusCallback(
	__in  HINTERNET hInternet,
	__in  DWORD_PTR dwContext,
	__in  DWORD dwInternetStatus,
	__in  LPVOID lpvStatusInformation,
	__in  DWORD dwStatusInformationLength
)
{
	UNREFERENCED_PARAMETER(hInternet);
	UNREFERENCED_PARAMETER(dwContext);

	long lStatus = 0;
	if (lpvStatusInformation != nullptr)
	{
		lStatus = *(long*)lpvStatusInformation;
	}
	string strInternetStatus = to_string(dwInternetStatus);
	// Since this method is called multiple times for each request, log the extended info only for 12175 WINHTTP_CALLBACK_STATUS_SECURE_FAILURE
	//DebugPrint("WinHttpStatusCallback - InternetStatus: " + strInternetStatus + ", StatusInformation: " + to_string(lStatus));
	switch (dwInternetStatus)
	{
		case WINHTTP_CALLBACK_STATUS_SECURE_FAILURE:
			// Log more detailed information for this error case
			// https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nc-winhttp-winhttp_status_callback#winhttp_callback_status_shutdown_complete
			if (lpvStatusInformation && dwStatusInformationLength == sizeof(ULONG))
			{
				string strDetail;
				switch (lStatus)
				{
					case WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID";
						break;
					case WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR:
						strDetail = "WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR";
						break;
				}

				Print("SECURE_FAILURE with status info: " + strDetail);
			}
			break;
	}
}

string Endpoint::SendRequest(const string& endpoint, std::string sdata, const RequestMethod& method)
{
	// Prepare the parameters
	wstring wHostname = Get_utf16(PrivacyIDEA::ws2s(_hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = Get_utf16((PrivacyIDEA::ws2s(_path) + endpoint), CP_UTF8);

	LPSTR data = _strdup(sdata.c_str());
	const DWORD data_len = (DWORD)strnlen_s(sdata.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

	if (endpoint != PI_ENDPOINT_POLL_TX)
	{
		DebugPrint(L"Sending to: " + wHostname + fullPath);
		if (_logPasswords)
		{
			DebugPrint("data: " + std::string(data));
		}
		// !!! this can log the windows password in cleartext !!!
	}

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = nullptr;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = nullptr,
		hConnect = nullptr,
		hRequest = nullptr;

	// Check the windows version to decide which access type flag to set
	// TODO config already has this info, add shared_ptr to this class
	DWORD dwAccessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	if (info.dwMajorVersion == 6 && info.dwMinorVersion <= 2)
	{
		dwAccessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
		DebugPrint("Setting access type to WINHTTP_ACCESS_TYPE_DEFAULT_PROXY");
	}

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"privacyidea-cp",
		dwAccessType,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
	{
		// Set the callback and optionally a port other than default https
		WinHttpSetStatusCallback(
			hSession,
			(WINHTTP_STATUS_CALLBACK)WinHttpStatusCallback,
			WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
			NULL);

		int port = (_customPort != 0) ? _customPort : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), (INTERNET_PORT)port, 0);
	}
	else
	{
		Print("WinHttpOpen failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ENDPOINT_SETUP_ERROR;
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}
	// Create an HTTPS request handle. SSL indicated by WINHTTP_FLAG_SECURE
	if (hConnect)
	{
		hRequest = WinHttpOpenRequest(hConnect, requestMethod, fullPath.c_str(),
			NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	}
	else
	{
		Print("WinHttpOpenRequest failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ENDPOINT_SETUP_ERROR;
		return "";
	}

	// Set Option Security Flags to start TLS
	DWORD dwReqOpts = 0;
	if (WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwReqOpts, sizeof(DWORD)))
	{
	}
	else
	{
		Print("WinHttpSetOption to set TLS flag failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ENDPOINT_SETUP_ERROR;
		return "";//ENDPOINT_ERROR_SETUP_ERROR;
	}

	/////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
	DWORD dwSSLFlags = 0;
	if (_ignoreUnknownCA)
	{
		dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		//DebugPrint("SSL ignore unknown CA flag set");
	}

	if (_ignoreInvalidCN)
	{
		dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		//DebugPrint("SSL ignore invalid CN flag set");
	}

	if (_ignoreUnknownCA || _ignoreInvalidCN)
	{
		if (WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD)))
		{
			//DebugPrintLn("WinHttpOption flags set to ignore SSL errors");
		}
		else
		{
			Print("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
			_lastErrorCode = PI_ENDPOINT_SETUP_ERROR;
			return ""; //ENDPOINT_ERROR_SETUP_ERROR;
		}
	}
	///////////////////////////////////////////////////////////////////////////////

	// Set timeouts on the request handle
	if (!WinHttpSetTimeouts(hRequest, _resolveTimeout, _connectTimeout, _sendTimeout, _receiveTimeout))
	{
		Print("Failed to set timeouts on hRequest: " + to_string(GetLastError()));
		// Continue with defaults
	}

	// Define for POST to be recognized
	LPCWSTR additionalHeaders = L"Content-Type: application/x-www-form-urlencoded\r\n";

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(
			hRequest,
			additionalHeaders,
			(DWORD)-1,
			(LPVOID)data,
			data_len,
			data_len,
			0);

	if (!bResults)
	{
		// This happens in case of timeout using offline OTP vvv will be 120002
		Print("WinHttpSendRequest failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ENDPOINT_SERVER_UNAVAILABLE;
		return "";
	}

	// End the request.
	if (bResults)
	{
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}

	// Keep checking for data until there is nothing left.
	string response;
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				Print("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
				response = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[ULONGLONG(dwSize) + 1];
			if (!pszOutBuffer)
			{
				Print("WinHttpReadData out of memory: " + to_string(GetLastError()));
				response = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, (ULONGLONG)dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
					Print("WinHttpReadData error: " + to_string(GetLastError()));
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
		Print("WinHttp Result error: " + to_string(GetLastError()));
		response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
	}
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	SecureZeroMemory(data, data_len);

	if (std::find(_excludedEndpoints.begin(), _excludedEndpoints.end(), endpoint) == _excludedEndpoints.end())
	{
		if (!response.empty())
		{
			try
			{
				auto j = nlohmann::json::parse(response);
				DebugPrint(j.dump(4));
			}
			catch (json::exception& e)
			{
				DebugPrint("JSON parse exception: " + string(e.what()) + ", response was: " + response);
			}
		}
		else
		{
			DebugPrint("Response was empty.");
		}
	}

	if (response.empty())
	{
		_lastErrorCode = PI_ENDPOINT_SERVER_UNAVAILABLE;
	}

	return response;
}

std::string Endpoint::EncodePair(const std::string& key, const std::string& value)
{
	return std::string(key.c_str()) + "=" + EscapeUrl(value);
}

std::string Endpoint::EncodePair(const std::string& key, const std::wstring& value)
{
	return EncodePair(key, PrivacyIDEA::ws2s(value));
}

HRESULT Endpoint::ParseAuthenticationRequest(const string& in)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::TryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	auto jValue = j["result"]["value"];

	if (jValue.is_boolean())
	{
		return (jValue.get<boolean>() ? PI_AUTH_SUCCESS : PI_AUTH_FAILURE);
	}
	return PI_AUTH_FAILURE;
}

HRESULT Endpoint::ParseTriggerRequest(const std::string& in, Challenge& c)
{
	DebugPrint(__FUNCTION__);

	auto j = Endpoint::TryParseJSON(in);
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

		if (!type.empty())
		{

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

HRESULT Endpoint::ParseForError(const std::string& in, std::string& errMsg, int& errCode)
{
	DebugPrint(__FUNCTION__);
	auto j = Endpoint::TryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	// Check for error code and message
	auto error = j["result"]["error"];
	if (error.is_object())
	{
		auto jErrCode = error["code"];
		auto jErrMsg = error["message"];

		if (jErrCode.is_number() && jErrMsg.is_string())
		{
			errCode = jErrCode.get<int>();
			errMsg = jErrMsg.get<std::string>();
			return PI_JSON_ERROR_CONTAINED;
		}
	}
	return E_FAIL;
}

const HRESULT& Endpoint::GetLastErrorCode()
{
	return _lastErrorCode;
}

HRESULT Endpoint::PollForTransaction(const std::string& data)
{
	string response = SendRequest(PI_ENDPOINT_POLL_TX, data, RequestMethod::GET);
	return ParseForTransactionSuccess(response);
}

HRESULT Endpoint::ParseForTransactionSuccess(const std::string& in)
{
	//DebugPrint(__FUNCTION__);

	auto j = Endpoint::TryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	auto jValue = j["result"]["value"];
	if (jValue.is_boolean())
	{
		return jValue.get<bool>() ? PI_TRANSACTION_SUCCESS : PI_TRANSACTION_FAILURE;
	}
	return PI_TRANSACTION_FAILURE;
}

HRESULT Endpoint::FinalizePolling(const std::string& user, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	// Finalize with empty pass
	std::string data = EncodePair("user", user) + "&" + EncodePair("transaction_id", transaction_id) + "&pass=";
	string response = SendRequest(PI_ENDPOINT_VALIDATE_CHECK, data, RequestMethod::POST);
	return ParseAuthenticationRequest(response);
}