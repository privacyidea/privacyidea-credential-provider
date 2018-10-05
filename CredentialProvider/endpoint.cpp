#include "endpoint.h"
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string.h>

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
			wcscpy_s(error, ARRAYSIZE(error), L"You could not be authenticated. Wrong credentials.");
			break;
		case (int)ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION:
			wcscpy_s(error, ARRAYSIZE(error), L"Insufficient subscription. The user count exceeds your subscription. ");
			break;
		case (int)ENDPOINT_ERROR_PARSE_ERROR:
		case (int)ENDPOINT_ERROR_NO_RESULT:
			wcscpy_s(error, ARRAYSIZE(error), L"An error occured while parsing the server's response");
			break;
			// WinHttp Errors
		case (int)ENDPOINT_ERROR_CONNECT_ERROR:
			wcscpy_s(error, ARRAYSIZE(error), L"An error occured while connecting to the server. Please check your configuration.");
			break;
		case (int)ENDPOINT_ERROR_SETUP_ERROR:
			wcscpy_s(error, ARRAYSIZE(error), L"An error occured while setting up the connection to the server. Please check your configuration.");
			break;
		case (int)ENDPOINT_ERROR_RESPONSE_ERROR:
			wcscpy_s(error, ARRAYSIZE(error), L"An error occured while processing the server's response.");
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
			wcscpy_s(msg, ARRAYSIZE(msg), L"Communicating with 2FA server...");
			break;
		case ENDPOINT_INFO_CHECKING_RESPONSE:
			wcscpy_s(msg, ARRAYSIZE(msg), L"Checking response...");
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
		// Create an instance of our BufferStruct to accept HttpRequest response
		struct Concrete::BufferStruct *output = (struct Concrete::BufferStruct *) malloc(sizeof(struct Concrete::BufferStruct));
		output->buffer = NULL;
		output->size = 0;

		struct ENDPOINT *epPack = Get();

		// && EMPTY(Get()->otpPass) makes the bools possibly only true in the first step. 
		// After the OTP filled the epPck these are always false indicating the "real" auth request
		bool sendEmptyPWFirst = Configuration::Get()->two_step_send_empty_password && EMPTY(Get()->otpPass);
		bool sendDomainPWFirst = Configuration::Get()->two_step_send_password && EMPTY(Get()->otpPass);
		bool hideOTP = Configuration::Get()->two_step_hide_otp && EMPTY(Get()->otpPass);

		/////////// FIRST STEP ///////////
		if (hideOTP && sendDomainPWFirst)
		{
			LAST_ERROR_CODE = Concrete::PrepareAndSendRequest(output, epPack->ldapPass);
		}
		else if (hideOTP && sendEmptyPWFirst)
		{
			LAST_ERROR_CODE = Concrete::PrepareAndSendRequest(output, L"");
		}
		else if (hideOTP && !sendEmptyPWFirst && !sendDomainPWFirst)
		{
			DebugPrintLn("Enter OTP in second step, no request sent yet");
			LAST_ERROR_CODE = ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE;
			result = ENDPOINT_AUTH_CONTINUE;
			STATUS = NOT_FINISHED;
		}
		////////////////////////////////////////////
		/////////// SECOND STEP	with OTP ///////////
		else
		{
			LAST_ERROR_CODE = Concrete::PrepareAndSendRequest(output, epPack->otpPass);
		}
		////////////////////////////////////////////

		if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_RESPONSE_OK)
		{	// Request successful
			ShowInfoMessage(ENDPOINT_INFO_CHECKING_RESPONSE);
			// Parse and check JSON response
			char* json = output->buffer;
			LAST_ERROR_CODE = Concrete::CheckJSONResponse(json);
		}

		ShowInfoMessage(ENDPOINT_INFO_PLEASE_WAIT);

		// TRANSLATE HRESULT TO BASE DEFINITIONS
		if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_VALUE_TRUE)
		{
			DebugPrintLn("Verification successfull :)");
			result = ENDPOINT_AUTH_OK; // Default success code
			STATUS = FINISHED;
		}
		else
		{
			if (hideOTP || sendEmptyPWFirst || sendDomainPWFirst)
			{	// we were in the first step so we want to continue
				DebugPrintLn("Second step of verification required :)");
				LAST_ERROR_CODE = ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE;
				result = ENDPOINT_AUTH_CONTINUE;
				STATUS = NOT_FINISHED;
			}
			else
			{
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
		std::string checkPath(std::string path) {
			// check if there is a path, if it starts with slash and append /validate/check
			std::string tmp = path;

			std::string compare("/path/to/pi");	// this is the default from the installer, check it here so the hint stays in the registry
			if (tmp == compare || tmp.empty()) {
				// path is "empty" so we return only /validate/check
				return ENDPOINT_VALIDATE_CHECK;
			}

			std::string slash("/");
			if (strncmp(path.c_str(), slash.c_str(), slash.size()) != 0) {
				// path does not start with /, so we prepend it
				return slash + tmp + ENDPOINT_VALIDATE_CHECK;
			}

			// path contains a valid path
			return tmp + ENDPOINT_VALIDATE_CHECK;
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
			DWORD data_len = strnlen_s(data,4096);

			std::wstring hostname = get_utf16(domain, CP_UTF8);
			std::wstring path = get_utf16(url, CP_UTF8);
			std::string response;

#ifdef _DEBUG
			DebugPrintLn("WinHttp sending to:");
			DebugPrintLn(hostname.c_str());
			DebugPrintLn(path.c_str());
			if (Configuration::Get()->log_sensitive) {
				DebugPrintLn("post_data:");
				DebugPrintLn(data);			// !!! this can show the windows password in cleartext !!! 
			}
			
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
				// check if custom port is set
				if (Configuration::Get()->custom_port != 0) {
					hConnect = WinHttpConnect(hSession, hostname.c_str(),
						Configuration::Get()->custom_port, 0);
				}
				else {
					hConnect = WinHttpConnect(hSession, hostname.c_str(),
						INTERNET_DEFAULT_HTTPS_PORT, 0);
				}
			}
			else {
				DebugPrintLn("WinHttpOpen failure:");
				DebugPrintLn(GetLastError());
				if (Configuration::Get()->release_log) {
					writeToLog("WinHttpOpen failure:");
					writeToLog(GetLastError());
					writeToLog("Trying to send to:");
					writeToLog(hostname.c_str());
					writeToLog(path.c_str());
				}
				return ENDPOINT_ERROR_SETUP_ERROR;
			}
			// Create an HTTPS request handle. SSL indicated by WINHTTP_FLAG_SECURE
			if (hConnect) {
				hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
					NULL, WINHTTP_NO_REFERER,
					WINHTTP_DEFAULT_ACCEPT_TYPES,
					WINHTTP_FLAG_SECURE);
			}
			else {
				DebugPrintLn("WinHttpOpenRequest failure:");
				DebugPrintLn(GetLastError());
				if (Configuration::Get()->release_log) {
					writeToLog("WinHttpOpenRequest failure:");
					writeToLog(GetLastError());
					writeToLog("Trying to send to:");
					writeToLog(hostname.c_str());
					writeToLog(path.c_str());
				}
				return ENDPOINT_ERROR_SETUP_ERROR;
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
				DebugPrintLn("WinHttpOptions security flag could not be set:");
				DebugPrintLn(GetLastError());
				if (Configuration::Get()->release_log) {
					writeToLog("WinHttpOptions security flag could not be set:");
					writeToLog(GetLastError());
				}
				return ENDPOINT_ERROR_SETUP_ERROR;
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
				if (WinHttpSetOption(hRequest,
					WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD))) {
					//DebugPrintLn("WinHttpOption flags set to ignore SSL errors");
				}
				else {
					DebugPrintLn("WinHttpOption flags could not be set:");
					DebugPrintLn(GetLastError());
					if (Configuration::Get()->release_log) {
						writeToLog("WinHttpOption flags could not be set:");
						writeToLog(GetLastError());
					}
					return ENDPOINT_ERROR_SETUP_ERROR;
				}
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
				DebugPrintLn("WinHttpSendRequest failure:");
				DebugPrintLn(GetLastError());
				if (Configuration::Get()->release_log) {
					writeToLog("WinHttpSendRequest failure:");
					writeToLog(GetLastError());
					writeToLog("Trying to send to:");
					writeToLog(hostname.c_str());
					writeToLog(path.c_str());
				}
				return ENDPOINT_ERROR_CONNECT_ERROR;
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
						if (Configuration::Get()->release_log) {
							writeToLog("WinHttpQueryDataAvailable error:");
							writeToLog(GetLastError());
						}
						result = ENDPOINT_ERROR_RESPONSE_ERROR;
					}

					// Allocate space for the buffer.
					pszOutBuffer = new char[dwSize + 1];
					if (!pszOutBuffer)
					{
						DebugPrintLn("WinHttpReadData out of memory");
						if (Configuration::Get()->release_log) {
							writeToLog("WinHttpReadData out of memory");
						}
						result = ENDPOINT_ERROR_RESPONSE_ERROR;
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
							if (Configuration::Get()->release_log) {
								writeToLog("WinHttpReadData Error:");
								writeToLog(GetLastError());
							}
							result = ENDPOINT_ERROR_RESPONSE_ERROR;
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
				if (Configuration::Get()->release_log) {
					writeToLog("WinHttp Result Error:");
					writeToLog(GetLastError());
				}
				result = ENDPOINT_ERROR_RESPONSE_ERROR;
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

		HRESULT PrepareAndSendRequest(struct BufferStruct *&buffer, wchar_t *pass)
		{
			DebugPrintLn(__FUNCTION__);

			// Pack the data for post request
			INIT_ZERO_CHAR(post_data, 4096);
			INIT_ZERO_CHAR(username, 64);
			INIT_ZERO_CHAR(passToSend, 64);
			struct ENDPOINT *epPack = Get();
			Helper::WideCharToChar(epPack->username, sizeof(username) / sizeof(char), username);
			Helper::WideCharToChar(pass, sizeof(passToSend) / sizeof(char), passToSend);
			sprintf_s(post_data, sizeof(post_data) / sizeof(char),
				"pass=%s&user=%s",
				passToSend,
				username
			);

			HRESULT result = ENDPOINT_ERROR_HTTP_ERROR;
			// Get hostname and path
			std::string hostname(Configuration::Get()->hostname);	// hostname from registry
			std::string data(post_data);							// post_data already contains the payload correctly encoded
			std::string path(Configuration::Get()->path);			// path from registry

			path = checkPath(path);

			result = SendPOSTRequest(hostname, path, data, buffer);

			if (result == 0) {
				result = ENDPOINT_SUCCESS_RESPONSE_OK;
			}
			
			return result;
		}

		HRESULT CheckJSONResponse(char *&json)
		{
			DebugPrintLn(__FUNCTION__);

			DebugPrintLn("Plain JSON response:");
			DebugPrintLn(json);

			HRESULT result = E_FAIL;

			if (json == NULL) {
				if (Configuration::Get()->release_log) {
					writeToLog("JSON response was null: ENDPOINT_ERROR_JSON_NULL");
				}
				return ENDPOINT_ERROR_JSON_NULL;
			}

			// 1. Parse a JSON string into DOM.
			rapidjson::Document json_document;
			json_document.Parse(json);

			if (json_document.HasParseError())
			{
				DebugPrintLn("Parse error at:");
				DebugPrintLn(static_cast<unsigned int>(json_document.GetErrorOffset()));
				DebugPrintLn("Parse error description:");
				DebugPrintLn(GetParseError_En(json_document.GetParseError()));
				if (Configuration::Get()->release_log) {
					writeToLog("JSON parse error: ENDPOINT_ERROR_PARSE_ERROR");
					writeToLog("Plaintext response:");
					writeToLog(json);
				}
				return ENDPOINT_ERROR_PARSE_ERROR;
			}

			// 2. Get result-object
			if (!json_document.HasMember("result")) {
				if (Configuration::Get()->release_log) {
					writeToLog("Response has no member 'result': ENDPOINT_ERROR_NO_RESULT");
					writeToLog("Plaintext response:");
					writeToLog(json);
				}
				return ENDPOINT_ERROR_NO_RESULT;
			}

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
					// This is also reached in case of sending the username and pw to privacyideaIDEA (two step)
					if (Configuration::Get()->release_log && !Configuration::Get()->two_step_send_password) {
						writeToLog("Response has no member 'value': ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER");
						writeToLog("Plaintext response:");
						writeToLog(json);
					}
					result = ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER;
				}
			}
			else
			{
				// No Member "status" or "status" = false
				result = ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;

				// Check if error is present
				if (!json_result.HasMember("error")) {
					if (Configuration::Get()->release_log) {
						writeToLog("Response has no member 'error': ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER");
						writeToLog("Plaintext response:");
						writeToLog(json);
					}
					return ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER;
				}

				// Check for error code
				rapidjson::Value& json_error = json_result["error"];
				rapidjson::Value::MemberIterator json_error_code = json_error.FindMember("code");

				if (json_error_code->value.GetInt() == ENDPOINT_RESPONSE_INSUFFICIENT_SUBSCR) {
					if (Configuration::Get()->release_log) {
						writeToLog("Insufficient subscription error: ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION");
						writeToLog("Plaintext response:");
						writeToLog(json);
					}
					result = ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION;
				}
			}
			return result;
		}

	} // Namespace Concrete

} // Namespace Endpoint
