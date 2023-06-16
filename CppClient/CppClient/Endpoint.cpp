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
#include "Convert.h"
#include <winhttp.h>
#include <atlutil.h>

#pragma comment(lib, "winhttp.lib")

#define PRINT_ENDPOINT_RESPONSES

using namespace std;

vector<std::string> _excludedEndpoints = { PI_ENDPOINT_POLLTRANSACTION };

HRESULT Endpoint::GetLastErrorCode()
{
	return _lastErrorCode;
}

std::string Endpoint::URLEncode(const std::string& in)
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
		Print("AtlEscapeUrl Failure " + to_string(GetLastError()));
	}

	SecureZeroMemory(buf, (sizeof(char) * maxLen));
	free(buf);
	return ret;
}

std::string Endpoint::EncodeRequestParameters(const std::map<std::string, std::string>& parameters)
{
	DebugPrint("Request parameters:");
	string ret;
	for (auto& entry : parameters)
	{
		auto encoded = URLEncode(entry.second);
		ret += entry.first + "=" + encoded + "&";
		if (entry.first != "pass" || _config.logPasswords)
		{
			DebugPrint(entry.first + "=" + encoded);
		}
		else
		{
			DebugPrint("pass parameter is not logged");
		}
	}

	// Cut trailing &
	if (ret.size() > 1)
	{
		ret = ret.substr(0, ret.size() - 1);
	}
	return ret;
}

wstring Endpoint::EncodeUTF16(const std::string& str, int codepage)
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

string Endpoint::SendRequest(const std::string& endpoint, const std::map<std::string, std::string>& parameters, const RequestMethod& method)
{
	DebugPrint(string(__FUNCTION__) + " to " + endpoint);
	// Prepare the parameters
	wstring wHostname = EncodeUTF16(Convert::ToString(_config.hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = EncodeUTF16((Convert::ToString(_config.path) + endpoint), CP_UTF8);

	string strData = EncodeRequestParameters(parameters);

	LPSTR data = _strdup(strData.c_str());
	const DWORD data_len = (DWORD)strnlen_s(strData.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = nullptr;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = nullptr, hConnect = nullptr, hRequest = nullptr;

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

		int port = (_config.customPort != 0) ? _config.customPort : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), (INTERNET_PORT)port, 0);
	}
	else
	{
		Print("WinHttpOpen failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
		return "";
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
		_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
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
		_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
		return "";
	}

	/////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
	DWORD dwSSLFlags = 0;
	if (_config.ignoreUnknownCA)
	{
		dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		//DebugPrint("SSL ignore unknown CA flag set");
	}

	if (_config.ignoreInvalidCN)
	{
		dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		//DebugPrint("SSL ignore invalid CN flag set");
	}

	if (_config.ignoreUnknownCA || _config.ignoreInvalidCN)
	{
		if (WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD)))
		{
			//DebugPrintLn("WinHttpOption flags set to ignore SSL errors");
		}
		else
		{
			Print("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
			_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
			return "";
		}
	}
	///////////////////////////////////////////////////////////////////////////////

	// Set timeouts on the request handle
	if (!WinHttpSetTimeouts(hRequest, _config.resolveTimeout, _config.connectTimeout, _config.sendTimeout, _config.receiveTimeout))
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
		_lastErrorCode = PI_ERROR_SERVER_UNAVAILABLE;
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
			DebugPrint(JsonParser::PrettyFormatJson(response));
		}
		else
		{
			DebugPrint("Response was empty.");
		}
	}

	if (response.empty())
	{
		_lastErrorCode = PI_ERROR_SERVER_UNAVAILABLE;
	}

	return response;
}
