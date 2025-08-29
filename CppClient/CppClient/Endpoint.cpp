/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2025 NetKnights GmbH
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
#include <set>

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
		PIDebug("malloc fail");
		return "";
	}
	std::string ret;

	if (AtlEscapeUrl(in.c_str(), buf, pdwWritten, (DWORD)maxLen, ATL_URL_ENCODE_PERCENT))
	{
		ret = std::string(buf);
	}
	else
	{
		PIError("AtlEscapeUrl Failure " + to_string(GetLastError()));
	}

	SecureZeroMemory(buf, (sizeof(char) * maxLen));
	free(buf);
	return ret;
}

std::string Endpoint::EncodeRequestParameters(const std::map<std::string, std::string>& parameters)
{
    PIDebug("Request parameters:");
    static const std::set<std::string> noEncodeKeys = {
        "credential_id",
        "clientDataJSON",
        "attestationObject",
        "rawId"
    };

    std::string ret;
    for (const auto& entry : parameters)
    {
        std::string encoded;
        if (noEncodeKeys.count(entry.first) > 0) {
            encoded = entry.second; // Do not encode
        } else {
            encoded = URLEncode(entry.second);
        }
        ret += entry.first + "=" + encoded + "&";
        if (entry.first != "pass" || _config.logPasswords)
        {
            PIDebug(entry.first + "=" + encoded);
        }
        else
        {
            PIDebug("pass parameter is not logged");
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
			if (lpvStatusInformation && dwStatusInformationLength == sizeof(DWORD))
			{
				DWORD statusFlags = *(DWORD*)lpvStatusInformation;
				string strDetail;

				struct FlagString
				{
					DWORD flag;
					const char* name;
				};

				const FlagString flagStrings[] = {
					{ WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED, "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT, "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED, "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID, "WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID, "WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID" },
					{ WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR, "WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR" }
				};

				for (const auto& flagStr : flagStrings)
				{
					if (statusFlags & flagStr.flag)
					{
						if (!strDetail.empty())
						{
							strDetail += " | ";
						}
						strDetail += flagStr.name;
					}
				}

				if (strDetail.empty())
				{
					strDetail = "Unknown SECURE_FAILURE flag(s): " + std::to_string(statusFlags);
				}

				PIError("SECURE_FAILURE with status info: " + strDetail);
			}
			break;
	}
}

string Endpoint::SendRequest(const std::string& endpoint, const std::map<std::string, std::string>& parameters,
	const std::map<std::string, std::string>& headers, const RequestMethod& method)
{
	PIDebug(string(__FUNCTION__) + " to " + endpoint);
	// Prepare the parameters
	wstring wHostname = EncodeUTF16(Convert::ToString(hostname), CP_UTF8);
	// the api endpoint needs to be appended to the path then converted, because the "full path" is set separately in winhttp
	wstring fullPath = EncodeUTF16((Convert::ToString(path) + endpoint), CP_UTF8);

	string encodedData = EncodeRequestParameters(parameters);

	std::map<std::string, std::string> headersCopy = headers;
	// Validation of _config.acceptLanguage is done prior to this
	headersCopy.try_emplace("Accept-Language", _config.acceptLanguage);

#ifdef _DEBUG
	PIDebug("Headers:");
	PIDebug(L"User-Agent=" + _config.userAgent);
	for (auto& entry : headersCopy)
	{
		PIDebug(entry.first + "=" + entry.second);
	}
#endif //_DEBUG

	LPSTR data = _strdup(encodedData.c_str());
	DWORD dataLen = (DWORD)strnlen_s(encodedData.c_str(), MAXDWORD32);
	LPCWSTR requestMethod = (method == RequestMethod::GET ? L"GET" : L"POST");

	if (method == RequestMethod::GET)
	{
		fullPath += L"?" + EncodeUTF16(encodedData, CP_UTF8);
		data = nullptr; // No data needed for GET requests
		dataLen = 0; // No data length for GET requests
	}

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = nullptr;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = nullptr, hConnect = nullptr, hRequest = nullptr;

	// Check the windows version to decide which access type flag to set
	DWORD dwAccessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	if (info.dwMajorVersion == 6 && info.dwMinorVersion <= 2)
	{
		dwAccessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
		PIDebug("Setting access type to WINHTTP_ACCESS_TYPE_DEFAULT_PROXY");
	}

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(_config.userAgent.c_str(),
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

		int realPort = (port != 0) ? port : INTERNET_DEFAULT_HTTPS_PORT;
		hConnect = WinHttpConnect(hSession, wHostname.c_str(), (INTERNET_PORT)realPort, 0);
	}
	else
	{
		PIError("WinHttpOpen failure: " + to_string(GetLastError()));
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
		PIError("WinHttpOpenRequest failure: " + to_string(GetLastError()));
		_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
		return "";
	}

	// Set Option Security Flags to start TLS
	DWORD dwReqOpts = 0;
	if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwReqOpts, sizeof(DWORD)))
	{
		PIError("WinHttpSetOption to set TLS flag failure: " + to_string(GetLastError()));
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
			PIError("WinHttpSetOption for SSL flags failure: " + to_string(GetLastError()));
			_lastErrorCode = PI_ERROR_ENDPOINT_SETUP;
			return "";
		}
	}
	///////////////////////////////////////////////////////////////////////////////

	// Set timeouts on the request handle
	if (!WinHttpSetTimeouts(hRequest, _config.resolveTimeout, _config.connectTimeout, _config.sendTimeout, _config.receiveTimeout))
	{
		PIError("Failed to set timeouts on hRequest: " + to_string(GetLastError()));
		// Continue with defaults
	}

	// Add headers to the request
	wstring userAgent = L"User-Agent: " + _config.userAgent;
	if (!WinHttpAddRequestHeaders(hRequest, userAgent.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD))
	{
		PIError("Failed to add User-Agent to header!");
	}
	if (!headersCopy.empty())
	{
		for (auto& entry : headersCopy)
		{
			if (!entry.first.empty() && !WinHttpAddRequestHeaders(hRequest,	Convert::ToWString(entry.first + ": " + entry.second).c_str(),
				(DWORD)-1L,	WINHTTP_ADDREQ_FLAG_ADD))
			{
				PIError("Failed to add header " + entry.first + ": " + entry.second + " to request: " + to_string(GetLastError()));
			}
		}
	}

	// Send the request
	if (hRequest)
	{
		bResults = WinHttpSendRequest(
			hRequest,
			L"Content-Type: application/x-www-form-urlencoded\r\n",
			(DWORD)-1,
			(LPVOID)data,
			dataLen,
			dataLen,
			0);
	}

	if (!bResults)
	{
		// This happens in case of timeout using offline OTP vvv will be 120002
		PIError("WinHttpSendRequest failure: " + to_string(GetLastError()));
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
				PIError("WinHttpQueryDataAvailable failure: " + to_string(GetLastError()));
				response = ""; //ENDPOINT_ERROR_RESPONSE_ERROR;
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[ULONGLONG(dwSize) + 1];
			if (!pszOutBuffer)
			{
				PIError("WinHttpReadData out of memory: " + to_string(GetLastError()));
				response = ""; // ENDPOINT_ERROR_RESPONSE_ERROR;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, (ULONGLONG)dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
					PIError("WinHttpReadData error: " + to_string(GetLastError()));
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
		PIError("WinHttp Result error: " + to_string(GetLastError()));
		response = "";// ENDPOINT_ERROR_RESPONSE_ERROR;
	}
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	SecureZeroMemory(data, dataLen);

	if (std::find(_excludedEndpoints.begin(), _excludedEndpoints.end(), endpoint) == _excludedEndpoints.end())
	{
		if (!response.empty())
		{
			PIDebug(JsonParser::PrettyFormatJson(response));
		}
		else
		{
			PIDebug("Response was empty.");
		}
	}

	if (response.empty())
	{
		_lastErrorCode = PI_ERROR_SERVER_UNAVAILABLE;
	}

	return response;
}
