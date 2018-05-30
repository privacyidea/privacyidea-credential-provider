#include "endpoint.h"
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>

#pragma comment(lib,"winhttp.lib")

namespace Endpoint
{

	/////////////////////////
	/////////////////////// BASE ENDPOINT FUNCTIONALITY
	/////////////////////////

	ENDPOINT*& Get()
	{
		static struct ENDPOINT *epPck = NULL;

		return epPck;
	}

	void Default()
	{
		struct ENDPOINT*& epPck = Get();

		if (epPck == NULL || epPck->protectMe == true)
			return;

		ZERO(epPck->username);
		ZERO(epPck->ldapPass);
		ZERO(epPck->otpPass);
	}

	void Init()
	{
		DebugPrintLn(__FUNCTION__);

		struct ENDPOINT*& epPck = Get();

		if (epPck == NULL /*|| (epPck != NULL && !epPck->protectMe)*/)
		{
			epPck = (struct ENDPOINT*) malloc(sizeof(struct ENDPOINT));

			STATUS = READY;
			epPck->protectMe = false;
		}

		Default();
	}

	void Deinit()
	{
		DebugPrintLn(__FUNCTION__);

		struct ENDPOINT*& epPck = Get();

		Default();

		if (epPck != NULL && epPck->protectMe == false)
		{
			free(epPck);
			epPck = NULL;

			STATUS = NOT_READY;
		}
	}

	ENDPOINT_STATUS GetStatus()
	{
		return STATUS;
	}

	HRESULT GetLastErrorCode()
	{
		return LAST_ERROR_CODE;
	}

	void GetLastErrorDescription(wchar_t(&error)[ENDPOINT_ERROR_MSG_SIZE])
	{
		DebugPrintLn(__FUNCTION__);
		DebugPrintLn(LAST_ERROR_CODE);

		//if (!SUCCEEDED(LAST_ERROR_CODE)) {
		switch ((int)LAST_ERROR_CODE) {
			// CheckJSONResponse
		case (int)ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER:
			wcscpy_s(error, ARRAYSIZE(error), L"Service could not handle request.");
			break;
		case (int)ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER:
			wcscpy_s(error, ARRAYSIZE(error), L"You could not be authenticated. Wrong username or password?");
			break;
		case (int)ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION: 
			wcscpy_s(error, ARRAYSIZE(error), L"Insufficient subscription. The user count exceeds your subscription. ");
			break;
		case (int)ENDPOINT_ERROR_PARSE_ERROR:
		case (int)ENDPOINT_ERROR_NO_RESULT:
			wcscpy_s(error, ARRAYSIZE(error), L"Error reading service response.");
			break;
			// WinHttp Errors
		case (int)ENDPOINT_ERROR_CERT_ERROR:
			wcscpy_s(error, ARRAYSIZE(error), L"There was an error with the servers certificate.");
			break;

			/*case (int)ENDPOINT_CUSTOM_MESSAGE:
				wcscpy_s(error, ARRAYSIZE(error), Get()->custom_message);
				break;
				*/
		default:
			break;
		}
		//}
	}

	void GetLastInstructionDescription(wchar_t(&msg)[ENDPOINT_INSTRUCTION_MSG_SIZE], bool *&big)
	{
		DebugPrintLn(__FUNCTION__);

		UNREFERENCED_PARAMETER(msg);
		UNREFERENCED_PARAMETER(big);

		//if (SUCCEEDED(LAST_ERROR_CODE)) {
		switch ((int)LAST_ERROR_CODE) {
		case (int)ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE:
			wcscpy_s(msg, ARRAYSIZE(msg), L"Please enter your second factor.");
			big = false;
			break;
		default:
			break;
		}
		//}
	}

	void GetInfoMessage(wchar_t(&msg)[ENDPOINT_INFO_MSG_SIZE], long msg_code)
	{
		DebugPrintLn(__FUNCTION__);

		switch (msg_code) {
		case ENDPOINT_INFO_PLEASE_WAIT:
			wcscpy_s(msg, ARRAYSIZE(msg), L"Please wait...");
			break;
		case ENDPOINT_INFO_CALLING_ENDPOINT:
			wcscpy_s(msg, ARRAYSIZE(msg), L"Calling endpoint...");
			break;
		case ENDPOINT_INFO_CHECKING_RESPONSE:
			wcscpy_s(msg, ARRAYSIZE(msg), L"Checking response...");
			break;
		case ENDPOINT_ERROR_CERT_ERROR_MSG:
			wcscpy_s(msg, ARRAYSIZE(msg), L"An Error occured while verifying the servers certificate!");
			break;
		default:
			break;
		}
	}

	void ShowInfoMessage(long msg_code)
	{
		DebugPrintLn(__FUNCTION__);

		if (Data::Credential::Get()->pqcws == NULL)
			return;

		wchar_t msg[ENDPOINT_INFO_MSG_SIZE];
		GetInfoMessage(msg, msg_code);

		Data::Credential::Get()->pqcws->SetStatusMessage(msg);
	}

	HRESULT Call()
	{
		DebugPrintLn(__FUNCTION__);
		HRESULT result = ENDPOINT_AUTH_FAIL;

		// Do WebAPI call
		ShowInfoMessage(ENDPOINT_INFO_CALLING_ENDPOINT);

		struct Concrete::BufferStruct *output = (struct Concrete::BufferStruct *) malloc(sizeof(struct Concrete::BufferStruct)); // Create an instance of out BufferStruct to accept LCs output
		output->buffer = NULL;
		output->size = 0;

		bool firstStep = Configuration::Get()->two_step_send_password && EMPTY(Get()->otpPass);

		if (firstStep) {
			LAST_ERROR_CODE = Concrete::SendValidateCheckRequestLDAP(output);
			//DebugPrintLn("SENDrequestLDAP");
		}
		else {
			LAST_ERROR_CODE = Concrete::SendValidateCheckRequestOTP(output);
			//DebugPrintLn("SENDrequestOTP");
		}

		if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_RESPONSE_OK) // Request successful
		{
			ShowInfoMessage(ENDPOINT_INFO_CHECKING_RESPONSE);
			// Parse and check JSON response
			char* json = output->buffer;
			LAST_ERROR_CODE = Concrete::CheckJSONResponse(json);
		}

		ShowInfoMessage(ENDPOINT_INFO_PLEASE_WAIT);

		// Clean up
		if (output)
		{
			if (output->buffer)
			{
				free(output->buffer);
				output->buffer = NULL;
				output->size = 0;
			}
			free(output);
			output = NULL;
		}

		// TRANSLATE HRESULT TO BASE DEFINITIONS
		if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_VALUE_TRUE)
		{
			DebugPrintLn("Verification successfull :)");
			result = ENDPOINT_AUTH_OK; // Default success code
			STATUS = FINISHED;
		}
		else
		{
			if (firstStep) {
				DebugPrintLn("Second step of verification required :)");
				LAST_ERROR_CODE = ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE;
				result = ENDPOINT_AUTH_CONTINUE;
				STATUS = NOT_FINISHED;
			}
			else {
				DebugPrintLn("Verification failed :(");
				STATUS = NOT_FINISHED; // let him try again
			}
		}
		return result;
	}

	/////////////////////////
	/////////////////////// CONCRETE ENDPOINT FUNCTIONALITY
	/////////////////////////

	namespace Concrete
	{
		HRESULT replaceSubstring(std::string& str, const std::string& from, const std::string& to) {
			size_t start_pos = str.find(from);
			if (start_pos == std::string::npos)
				return E_FAIL;
			str.replace(start_pos, from.length(), to);
			return S_OK;
		}

		// return the path from the config entry e.g. /foo/bar/validate/check
		std::string getURL(std::string str) {
			std::string res;
			size_t pos = str.find("/", 0);
			if (pos != std::string::npos) {
				res = str.substr(pos, str.length() - 1);
				if (res.back() == '/') {
					res.erase(res.length() - 1);
				}
				return res + ENDPOINT_VALIDATE_CHECK;
			}
			else {// no path found in URL, return validate/check
				return ENDPOINT_VALIDATE_CHECK;
			}


		}

		std::wstring get_utf16(const std::string &str, int codepage)
		{
			if (str.empty()) return std::wstring();
			int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
			std::wstring res(sz, 0);
			MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
			return res;
		}

		HRESULT SendPOSTRequest(std::string domain, std::string url, std::string dat, struct BufferStruct *&buffer)
		{
			HRESULT result = S_OK;

			//Extra
			LPSTR  data = const_cast<char *>(dat.c_str());;
			DWORD data_len = strlen(data);

			std::wstring sdomain = get_utf16(domain, CP_UTF8);
			std::wstring surl = get_utf16(url, CP_UTF8);
			std::string response;

#ifdef _DEBUG
			DebugPrintLn("WinHttp sending to:");
			DebugPrintLn(sdomain.c_str());
			DebugPrintLn("post_data:");
			DebugPrintLn(data);
#endif

			DWORD dwSize = 0;
			DWORD dwDownloaded = 0;
			LPSTR pszOutBuffer;
			BOOL  bResults = FALSE;
			HINTERNET  hSession = NULL,
				hConnect = NULL,
				hRequest = NULL;

			// Use WinHttpOpen to obtain a session handle.
			hSession = WinHttpOpen(L"privacyidea-cp",
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
				WINHTTP_NO_PROXY_NAME,
				WINHTTP_NO_PROXY_BYPASS, 0);

			// Specify an HTTP server.
			if (hSession) {
				hConnect = WinHttpConnect(hSession, sdomain.c_str(),
					INTERNET_DEFAULT_HTTPS_PORT, 0);
			}
			// Create an HTTPS request handle. SSL indicated by WINHTTP_FLAG_SECURE
			if (hConnect) {
				hRequest = WinHttpOpenRequest(hConnect, L"POST", surl.c_str(),
					NULL, WINHTTP_NO_REFERER,
					WINHTTP_DEFAULT_ACCEPT_TYPES,
					WINHTTP_FLAG_SECURE);
			}

			// Set Option Security Flags to start TLS
			DWORD dwReqOpts = 0;
			if (WinHttpSetOption(
				hRequest,
				WINHTTP_OPTION_SECURITY_FLAGS,
				&dwReqOpts,
				sizeof(DWORD))) {
				DebugPrintLn("WinHttp TLS flag set");
			}

			/////////// SET THE FLAGS TO IGNORE SSL ERRORS, IF SPECIFIED /////////////////
			DWORD dwSSLFlags = 0;

			if (Configuration::Get()->ssl_ignore_unknown_ca) {
				dwSSLFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
				DebugPrintLn("SSL ignore unknown CA flag set");
			}

			if (Configuration::Get()->ssl_ignore_invalid_cn) {
				dwSSLFlags = dwSSLFlags | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
				DebugPrintLn("SSL ignore invalid CN flag set");
			}

			if (Configuration::Get()->ssl_ignore_unknown_ca || Configuration::Get()->ssl_ignore_invalid_cn) {
				WinHttpSetOption(hRequest,
					WINHTTP_OPTION_SECURITY_FLAGS,
					&dwSSLFlags,
					sizeof(DWORD));
				DebugPrintLn("WinHttp flags set to ignore SSL errors");
			}
			///////////////////////////////////////////////////////////////////////////////

			// Define for POST to be recognized
			LPCWSTR additionalHeaders = L"Content-Type: application/x-www-form-urlencoded\r\n";
			//DWORD headersLength = -1;

			// Send a request.
			if (hRequest)
				bResults = WinHttpSendRequest(hRequest,
					additionalHeaders, -1,
					(LPVOID)data, data_len,
					data_len, 0);

			if (!bResults) {
				DebugPrintLn("WinHttpSendRequest failed with error");
				result = GetLastError();

				DebugPrintLn(result);
				//DebugPrintLn(ERROR_WINHTTP_SECURE_FAILURE);

				if (result == ERROR_WINHTTP_SECURE_FAILURE) {
					DebugPrintLn("WinHttp Error: Cert Error");
					return ENDPOINT_ERROR_CERT_ERROR;
				}
				return ENDPOINT_ERROR_CERT_ERROR;
			}

			// End the request.
			if (bResults)
				bResults = WinHttpReceiveResponse(hRequest, NULL);

			// Keep checking for data until there is nothing left.
			if (bResults)
			{
				do
				{
					// Check for available data.
					dwSize = 0;
					if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
						DebugPrintLn("WinHttpQueryDataAvailable Error:");
						DebugPrintLn(GetLastError());
						result = E_FAIL;
						//printf("Error %u in WinHttpQueryDataAvailable.\n",
						//	GetLastError());
					}

					// Allocate space for the buffer.
					pszOutBuffer = new char[dwSize + 1];
					if (!pszOutBuffer)
					{
						DebugPrintLn("WinHttpReadData out of memory");
						//printf("Out of memory\n");
						result = E_FAIL;
						dwSize = 0;
					}
					else
					{
						// Read the data.
						ZeroMemory(pszOutBuffer, dwSize + 1);

						if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
							dwSize, &dwDownloaded)) {
							DebugPrintLn("WinHttpReadData Error:");
							DebugPrintLn(GetLastError());
							result = E_FAIL;
						}
						else
							//printf("%s", pszOutBuffer);
							response = response + std::string(pszOutBuffer);
						// Free the memory allocated to the buffer.
						delete[] pszOutBuffer;
					}
				} while (dwSize > 0);
			}
			// Report any errors.
			if (!bResults) {
				DebugPrintLn("WinHttp Result Error:");
				DebugPrintLn(GetLastError());
				result = E_FAIL;
				//printf("Error %d has occurred.\n", GetLastError());
			}
			// Close any open handles.
			if (hRequest) WinHttpCloseHandle(hRequest);
			if (hConnect) WinHttpCloseHandle(hConnect);
			if (hSession) WinHttpCloseHandle(hSession);

			// write response to bufferstruct
			buffer->buffer = _strdup(response.c_str());

			return result;
		}

		HRESULT SendRequestToServer(struct BufferStruct *&buffer, char *relativePath, int relativePathSize, char *post_data)
		{
			UNREFERENCED_PARAMETER(relativePath);
			UNREFERENCED_PARAMETER(relativePathSize);

			HRESULT result = ENDPOINT_ERROR_HTTP_ERROR;

			DebugPrintLn(__FUNCTION__);

			std::string domain(Configuration::Get()->server_url);	 // server url from registry
			std::string data(post_data);							// post_data already contains the payload for the request

			// check if the URL contains https:// and remove it if neccessary
			HRESULT hr = replaceSubstring(domain, "https://", "");
			if (SUCCEEDED(hr)) {
				//DebugPrintLn("https:// was found in the url and replaced");
			}
			// check if there is a path in the url to /validate/check
			std::string url = getURL(domain);

			result = SendPOSTRequest(domain, url, data, buffer);

			if (SUCCEEDED(result)) {
				result = ENDPOINT_SUCCESS_RESPONSE_OK;
			}

			return result;
		}

		HRESULT SendValidateCheckRequestOTP(struct BufferStruct *&buffer)
		{
			DebugPrintLn(__FUNCTION__);

			char *relativePath = ENDPOINT_VALIDATE_CHECK;

			HRESULT result = E_FAIL;

			INIT_ZERO_CHAR(post_data, 4096);
			INIT_ZERO_CHAR(username, 64);
			INIT_ZERO_CHAR(otpPass, 64);
			struct ENDPOINT *epPack = Get();

			Helper::WideCharToChar(epPack->username, sizeof(username) / sizeof(char), username);
			Helper::WideCharToChar(epPack->otpPass, sizeof(otpPass) / sizeof(char), otpPass);

			sprintf_s(post_data, sizeof(post_data) / sizeof(char),
				"pass=%s&user=%s",
				otpPass,
				username
			);

			result = SendRequestToServer(buffer, relativePath, (int)strlen(relativePath), post_data);
			return result;
		}

		HRESULT SendValidateCheckRequestLDAP(struct BufferStruct *&buffer)
		{
			DebugPrintLn(__FUNCTION__);

			char *relativePath = ENDPOINT_VALIDATE_CHECK;

			HRESULT result = E_FAIL;

			INIT_ZERO_CHAR(post_data, 4096);
			INIT_ZERO_CHAR(username, 64);
			INIT_ZERO_CHAR(ldapPass, 64);
			struct ENDPOINT *epPack = Get();

			Helper::WideCharToChar(epPack->username, sizeof(username) / sizeof(char), username);
			Helper::WideCharToChar(epPack->ldapPass, sizeof(ldapPass) / sizeof(char), ldapPass);

			sprintf_s(post_data, sizeof(post_data) / sizeof(char),
				"pass=%s&user=%s",
				ldapPass,
				username
			);

			result = SendRequestToServer(buffer, relativePath, (int)strlen(relativePath), post_data);

			return result;
		}

		HRESULT CheckJSONResponse(char *&json)
		{
			DebugPrintLn(__FUNCTION__);

			DebugPrintLn("Plain JSON response:");
			DebugPrintLn(json);

			HRESULT result = E_FAIL;

			if (json == NULL)
				return ENDPOINT_ERROR_JSON_NULL;

			// 1. Parse a JSON string into DOM.
			rapidjson::Document json_document;
			json_document.Parse(json);

			if (json_document.HasParseError())
			{
				DebugPrintLn("Parse error at:");
				DebugPrintLn(static_cast<unsigned int>(json_document.GetErrorOffset()));
				DebugPrintLn("Parse error description:");
				DebugPrintLn(GetParseError_En(json_document.GetParseError()));

				return ENDPOINT_ERROR_PARSE_ERROR;
			}

			// 2. Get result-object
			if (!json_document.HasMember("result"))
				return ENDPOINT_ERROR_NO_RESULT;

			rapidjson::Value& json_result = json_document["result"];

			// 3. Check result
			rapidjson::Value::MemberIterator json_status = json_result.FindMember("status");
			if (json_status != json_result.MemberEnd() && json_status->value.GetBool()) // request handled successfully?
			{
				result = ENDPOINT_SUCCESS_STATUS_TRUE;

				rapidjson::Value::MemberIterator json_value = json_result.FindMember("value");
				if (json_value != json_result.MemberEnd() && json_value->value.GetBool()) // authentication successfully?
				{
					result = ENDPOINT_SUCCESS_VALUE_TRUE;
				}
				else
				{
					// No Member "value" or "value" = false
					result = ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER;
				}
			}
			else
			{
				// No Member "status" or "status" = false
				result = ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;
				
				// Check if error is present
				if (!json_result.HasMember("error")) {
					return ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;
				}

				// Check for error code
				rapidjson::Value& json_error = json_result["error"];
				rapidjson::Value::MemberIterator json_error_code = json_error.FindMember("code");

				if (json_error_code->value.GetInt() == -500) {
					result = ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION;
				}

			}

			return result;
		}

	} // Namespace Concrete

} // Namespace Endpoint
