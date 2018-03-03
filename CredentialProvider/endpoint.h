#ifndef _ENDPOINT_H
#define _ENDPOINT_H
#pragma once

#define _SECURE_SCL 0

/////////////////////////
/////////////////////// BASE ENDPOINT INCLUDES
/////////////////////////

#include "common.h"
#include "config.h"

/////////////////////////
/////////////////////// CONCRETE ENDPOINT INCLUDES
/////////////////////////

#ifdef _DEBUG
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#endif

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"

#include "curl/curl.h"  
#include <time.h>

#include "rapidjson/stringbuffer.h"

//#include <iostream>

/////////////////////////
/////////////////////// BASE ENDPOINT DECLARATIONS
/////////////////////////

namespace Endpoint
{
	#define ENDPOINT_TIMEOUT_SECS	90

	#define ENDPOINT_AUTH_OK		((HRESULT)0x78809001)
	#define ENDPOINT_AUTH_FAIL		((HRESULT)0x88809001)
	#define ENDPOINT_AUTH_CONTINUE	((HRESULT)0x88809002)

	#define ENDPOINT_VALIDATE_CHECK	"/validate/check"

	enum ENDPOINT_STATUS 
	{
		NOT_READY		= 0,
		READY			= 1,
		FINISHED		= 2,
		NOT_FINISHED	= 3,
		WAITING			= 4,
		DATA_READY		= 5,
		SYNC_DATA		= 6,
		SHUTDOWN		= 7,
	};

	#define ENDPOINT_ERROR_MSG_SIZE 150
	#define ENDPOINT_INSTRUCTION_MSG_SIZE 150
	#define ENDPOINT_INFO_MSG_SIZE 150

	// TODO: dynamic data structure
	// !!! Match to concrete endpoint for project
	struct ENDPOINT
	{
		bool	protectMe = false; // Set to true, to protect from Deinit() and Default()

		//////

		wchar_t username[64];
		wchar_t ldapPass[64];
		wchar_t otpPass[64];
	};

	static ENDPOINT_STATUS STATUS = NOT_READY;
	static HRESULT LAST_ERROR_CODE = ENDPOINT_AUTH_FAIL;

	//static struct ENDPOINT_PACK *_epPck;

	ENDPOINT*& Get();
	void Default();
	void Init();
	void Deinit();
	HRESULT GetLastErrorCode();
	ENDPOINT_STATUS GetStatus();
	void GetLastErrorDescription(wchar_t (&error)[ENDPOINT_ERROR_MSG_SIZE]);
	void GetLastInstructionDescription(wchar_t(&msg)[ENDPOINT_INSTRUCTION_MSG_SIZE], bool *&big);
	void GetInfoMessage(wchar_t(&msg)[ENDPOINT_INFO_MSG_SIZE], long msg_code);
	void ShowInfoMessage(long msg_code);
	HRESULT Call();

	/////////////////////////
	/////////////////////// CONCRETE ENDPOINT DECLARATIONS
	/////////////////////////

	namespace Concrete
	{
		#define ENDPOINT_SUCCESS_DEBUG_OK					((HRESULT)0x78809AAA)

		#define ENDPOINT_ERROR_JSON_NULL					((HRESULT)0x88809004)
		#define ENDPOINT_ERROR_PARSE_ERROR					((HRESULT)0x88809005)
		#define ENDPOINT_ERROR_NO_RESULT					((HRESULT)0x88809006)
		#define ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER	((HRESULT)0x88809007)
		#define ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER		((HRESULT)0x88809008)
		#define ENDPOINT_ERROR_HTTP_REQUEST_FAIL			((HRESULT)0x88809009)
		#define ENDPOINT_ERROR_CURL_GLOBAL_INIT_FAIL		((HRESULT)0x8880900A)
		#define ENDPOINT_ERROR_CURL_EASY_INIT_FAIL			((HRESULT)0x8880900B)
		#define ENDPOINT_ERROR_CURL_RESPONSE_FAIL			((HRESULT)0x8880900C)

		#define ENDPOINT_ERROR_CURL_HTTP_NO_CODE_RECEIVED	((HRESULT)0x88809900)
		#define ENDPOINT_ERROR_CURL_HTTP_NOT_FOUND			((HRESULT)0x88809901)
		#define ENDPOINT_ERROR_CURL_HTTP_BAD_REQUEST		((HRESULT)0x88809902)
		#define ENDPOINT_ERROR_CURL_HTTP_UNAUTHORIZED		((HRESULT)0x88809903)
		#define ENDPOINT_ERROR_CURL_HTTP_FORBIDDEN			((HRESULT)0x88809904)
		#define ENDPOINT_ERROR_CURL_HTTP_ERROR				((HRESULT)0x8880990F)

		#define ENDPOINT_ERROR_EMPTY						((HRESULT)0x88809401)

		#define ENDPOINT_SUCCESS_STATUS_TRUE		((HRESULT)0x78809007)
		#define ENDPOINT_SUCCESS_VALUE_TRUE			((HRESULT)0x78809008)
		#define ENDPOINT_SUCCESS_HTTP_REQUEST_OK	((HRESULT)0x78809009)
		#define ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE	((HRESULT)0x7880900A)
		#define ENDPOINT_SUCCESS_CURL_RESPONSE_OK	((HRESULT)0x7880900C)

		#define ENDPOINT_INFO_PLEASE_WAIT			((long)0x00000001)
		#define ENDPOINT_INFO_CALLING_ENDPOINT		((long)0x00000002)
		#define ENDPOINT_INFO_CHECKING_RESPONSE		((long)0x00000003)

		#define CURL_SSL_VERIFY_PEER_TRUE  1L
		#define CURL_SSL_VERIFY_PEER_FALSE 0L

		#define CURL_SSL_VERIFY_HOST_TRUE  2L
		#define CURL_SSL_VERIFY_HOST_FALSE 0L

		// Define our struct for accepting LCs output
		struct BufferStruct
		{
			char * buffer;
			size_t size;
		};

		static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data);
		HRESULT SendRequestToServer(struct BufferStruct *&buffer, char *relativePath, int relativePathSize, char *post_data);
		HRESULT SendValidateCheckRequestLDAP(struct BufferStruct *&buffer);
		HRESULT SendValidateCheckRequestOTP(struct BufferStruct *&buffer);
		HRESULT CheckJSONResponse(char *&buffer);
	}
}

#endif
