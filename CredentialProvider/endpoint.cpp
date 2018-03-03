#include "endpoint.h"

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

void GetLastErrorDescription(wchar_t (&error)[ENDPOINT_ERROR_MSG_SIZE])
{
	DebugPrintLn(__FUNCTION__);

	//if (!SUCCEEDED(LAST_ERROR_CODE)) {
		switch ((int)LAST_ERROR_CODE) {
			// CheckJSONResponse
		case (int)ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER:
			wcscpy_s(error, ARRAYSIZE(error), L"Service could not handle request.");
			break;
		case (int)ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER:
			wcscpy_s(error, ARRAYSIZE(error), L"You could not be authenticated. Wrong username or password?");
			break;
		
		case (int)ENDPOINT_ERROR_PARSE_ERROR:
		case (int)ENDPOINT_ERROR_NO_RESULT:
			wcscpy_s(error, ARRAYSIZE(error), L"Error reading service response.");
			break;
			// SendRequestToServer
		case (int)ENDPOINT_ERROR_CURL_EASY_INIT_FAIL:
		case (int)ENDPOINT_ERROR_CURL_GLOBAL_INIT_FAIL:
			wcscpy_s(error, ARRAYSIZE(error), L"Service unreachable. HTTP init failed.");
			break;
		case (int)ENDPOINT_ERROR_CURL_RESPONSE_FAIL:
			wcscpy_s(error, ARRAYSIZE(error), L"Service unreachable. HTTP request failed.");
			break;
		/*case (int)ENDPOINT_CUSTOM_MESSAGE:
			wcscpy_s(error, ARRAYSIZE(error), Get()->custom_message);
			break;
			*/
			// Call
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
	}
	else {
		LAST_ERROR_CODE = Concrete::SendValidateCheckRequestOTP(output);
	}
		
	if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_CURL_RESPONSE_OK) // Request successful
	{
		ShowInfoMessage(ENDPOINT_INFO_CHECKING_RESPONSE);

		// Parse and check JSON respone
		char* json = output->buffer;

		LAST_ERROR_CODE = Concrete::CheckJSONResponse(json);
	}
#ifdef _DEBUG
	else if (LAST_ERROR_CODE == ENDPOINT_ERROR_CURL_HTTP_BAD_REQUEST)
	{
		// server is has no endpoint server connected during debugging
		LAST_ERROR_CODE = ENDPOINT_SUCCESS_DEBUG_OK;
	}
#endif

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
	if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_VALUE_TRUE || LAST_ERROR_CODE == ENDPOINT_SUCCESS_DEBUG_OK)
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
		} else {
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

static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;

	struct BufferStruct * mem = (struct BufferStruct *) data;

	mem->buffer = (char*) realloc(mem->buffer, mem->size + realsize + 1);

	if (mem->buffer)
	{
		memcpy(&(mem->buffer[ mem->size ]), ptr, realsize);
		mem->size += realsize;
		mem->buffer[mem->size] = 0;
	}

	return realsize;
}

HRESULT SendRequestToServer(struct BufferStruct *&buffer, char *relativePath, int relativePathSize, char *post_data)
{
	DebugPrintLn(__FUNCTION__);
	DebugPrintLn("Data to send:");
	DebugPrintLn(post_data);

#ifdef _DEBUG
	unsigned long start = time(NULL);
	{
		INIT_ZERO_CHAR(out, 1024);
		sprintf_s(out, sizeof(out) / sizeof(char), "TIME START: \t%d", start);
		DebugPrintLn(out);
	}
#endif

	CURL *curl;
	CURLcode res;

	HRESULT result = E_FAIL;

	INIT_ZERO_CHAR(url, sizeof(Configuration::Get()->server_url) + 150);

	/* In windows, this will init the winsock stuff */
	CURLcode init = curl_global_init(CURL_GLOBAL_ALL);

#ifdef _DEBUG
	{
		INIT_ZERO_CHAR(out, 1024);
		sprintf_s(out, sizeof(out) / sizeof(char), "TIME cURL INIT: \t+%d", (int)time(NULL) - start);
		DebugPrintLn(out);
	}
#endif

	if (init == CURLE_OK) { 
		/* get a curl handle */ 
		curl = curl_easy_init();
		
		if(curl) {
			/* First set the URL that is about to receive our POST. This URL can
			just as well be a https:// URL if that is what should receive the
			data. */ 
			strncat_s(url, sizeof(url), Configuration::Get()->server_url, sizeof(Configuration::Get()->server_url));
			
			strncat_s(url, sizeof(url), relativePath, relativePathSize);
			curl_easy_setopt(curl, CURLOPT_URL, url);

			DebugPrintLn("Request URL:");
			DebugPrintLn(url);

			/* Now specify the POST data */ 
			if (NOT_EMPTY(post_data))
			{
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
			}

			/* Eventually we define a callback to write the response data to a buffer */
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // Passing the function pointer to LC
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buffer); // Passing our BufferStruct to LC

			/* set if we want to disconnect if we can't validate server's cert */ 
			if (Configuration::Get()->ssl_verify_signature)
				curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER, CURL_SSL_VERIFY_PEER_TRUE);
			else
				curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER, CURL_SSL_VERIFY_PEER_FALSE);

			/* set if we want to disconnect if we can't validate server's hostname */ 
			if (Configuration::Get()->ssl_verify_hostname)
				curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST, CURL_SSL_VERIFY_HOST_TRUE);
			else
				curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST, CURL_SSL_VERIFY_HOST_FALSE);

			/* set a timeout for the request */
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, ENDPOINT_TIMEOUT_SECS);

#ifdef _DEBUG
			{
				INIT_ZERO_CHAR(out, 1024);
				sprintf_s(out, sizeof(out) / sizeof(char), "TIME cURL READY: \t+%d\nTIMEOUT AFTER: \t%is", (int)time(NULL) - start, ENDPOINT_TIMEOUT_SECS);
				DebugPrintLn(out);
			}
#endif

			/* Perform the request, res will get the return code */ 
			res = curl_easy_perform(curl);

#ifdef _DEBUG
			{
				INIT_ZERO_CHAR(out, 1024);
				sprintf_s(out, sizeof(out) / sizeof(char), "TIME cURL DONE: \t+%d", (int)time(NULL) - start);
				DebugPrintLn(out);
			}
#endif

			/* set a buffer to receive the HTTP response code */
			long http_code = 0;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

			DebugPrintLn("HTTP Response Code:");
			DebugPrintLn(http_code);

			/* Check for errors */ 
			if (res == CURLE_OK)
			{
				if (http_code == 0)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_NO_CODE_RECEIVED;
				}
				else if (http_code == 400)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_BAD_REQUEST;
				}
				else if (http_code == 401)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_UNAUTHORIZED;
				}
				else if (http_code == 403)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_FORBIDDEN;
				}
				else if (http_code == 404)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_NOT_FOUND;
				}
				else if (http_code != 200)
				{
					result = ENDPOINT_ERROR_CURL_HTTP_ERROR;
				}
				else {
					result = ENDPOINT_SUCCESS_CURL_RESPONSE_OK;
				}
			}
			else
			{
#ifdef _DEBUG
				DebugPrintLn(_strdup(curl_easy_strerror(res)));
#endif

				result = ENDPOINT_ERROR_CURL_RESPONSE_FAIL;
			}

			/* always cleanup */ 
			curl_easy_cleanup(curl);
		}
		else {
			result = ENDPOINT_ERROR_CURL_EASY_INIT_FAIL;
		}

		curl_global_cleanup();
	}
	else {
		result = ENDPOINT_ERROR_CURL_GLOBAL_INIT_FAIL;
	}

#ifdef _DEBUG
	{
		INIT_ZERO_CHAR(out, 1024);
		sprintf_s(out, sizeof(out) / sizeof(char), "TIME END: \t\t+%d", (int)time(NULL) - start);
		DebugPrintLn(out);
	}
#endif

	ZERO(url);

	if (NOT_EMPTY(post_data))
	{
		ZERO(post_data);
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
	}

	return result;
}  

} // Namespace Concrete

} // Namespace Endpoint
