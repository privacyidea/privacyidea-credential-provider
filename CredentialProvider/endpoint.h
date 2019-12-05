/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
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

#pragma once
#include <string>
#include <map>
#include <Windows.h>
#include <mutex>

#define ENDPOINT_SUCCESS_DEBUG_OK					((HRESULT)0x78809AAA)

#define ENDPOINT_ERROR_PARSE_ERROR					((HRESULT)0x88809005)
#define ENDPOINT_ERROR_NO_RESULT					((HRESULT)0x88809006)
#define ENDPOINT_ERROR_STATUS_FALSE_OR_NO_MEMBER	((HRESULT)0x88809007)
#define ENDPOINT_ERROR_VALUE_FALSE_OR_NO_MEMBER		((HRESULT)0x88809008)
#define ENDPOINT_ERROR_HTTP_REQUEST_FAIL			((HRESULT)0x88809009)
#define ENDPOINT_ERROR_INSUFFICIENT_SUBSCRIPTION	((HRESULT)0x8880900A)
#define ENDPOINT_ERROR_CONNECT_ERROR				((HRESULT)0x8880900B)
#define ENDPOINT_ERROR_SETUP_ERROR					((HRESULT)0x8880900C)
#define ENDPOINT_ERROR_RESPONSE_ERROR				((HRESULT)0x8880900D)
#define ENDPOINT_ERROR_EMPTY_RESPONSE				((HRESULT)0x8880990F)

#define ENDPOINT_SUCCESS_STATUS_TRUE				((HRESULT)0x78809007)
#define ENDPOINT_SUCCESS_VALUE_TRUE					((HRESULT)0x78809008)
#define ENDPOINT_SUCCESS_HTTP_REQUEST_OK			((HRESULT)0x78809009)
#define ENDPOINT_SUCCESS_AUTHENTICATION_CONTINUE	((HRESULT)0x7880900A)
#define ENDPOINT_SUCCESS_RESPONSE_OK				((HRESULT)0x7880900C)

#define ENDPOINT_INFO_PLEASE_WAIT					((long)0x00000001)
#define ENDPOINT_INFO_CALLING_ENDPOINT				((long)0x00000002)
#define ENDPOINT_INFO_CHECKING_RESPONSE				((long)0x00000003)
#define ENDPOINT_INFO_PROCESSING					((long)0x00000004)

#define ENDPOINT_RESPONSE_INSUFFICIENT_SUBSCR		(int)101

#define ENDPOINT_STATUS_AUTH_OK						((HRESULT)0x78809001)
#define ENDPOINT_STATUS_AUTH_FAIL					((HRESULT)0x88809001)
#define ENDPOINT_STATUS_AUTH_CONTINUE				((HRESULT)0x88809002)
#define ENDPOINT_STATUS_POLLING						((HRESULT)0x88809003)
#define ENDPOINT_STATUS_PUSH_CANCELLED				((HRESULT)0x88809004)

#define ENDPOINT_STATUS_NOT_SET						((HRESULT)0x7880900F)

#define PI_ENDPOINT_VALIDATE_CHECK "/validate/check"
#define PI_ENDPOINT_POLL_TX "/validate/polltransaction"

enum class RequestMethod {
	GET,
	POST
};

class Endpoint
{
public:
	Endpoint();
	~Endpoint() = default;
	Endpoint(const Endpoint& endpoint) = default;
	Endpoint& operator=(Endpoint const& endpoint);

	std::string connect(std::string endpoint, std::map<std::string, std::string> params, RequestMethod method);

	std::wstring get_utf16(const std::string& str, int codepage);

	std::string escapeUrl(const std::string& in);

	HRESULT parseAuthenticationRequest(std::string in);

	HRESULT parseTriggerRequest(std::string in);

	HRESULT parseForError(std::string in);

	HRESULT pollForTransactionWithLoop(std::string transaction_id);

	HRESULT pollForTransactionSingle(std::string transaction_id);

	HRESULT parseForTransactionSuccess(std::string in);

	HRESULT finalizePolling(std::string user, std::string transaction_id);

	HRESULT lastError = S_OK;

	void setRunPoll(bool val);

private:

	bool _runPoll = false;

	bool _ignoreInvalidCN = false;
	bool _ignoreUnknownCA = false;
	std::wstring _hostname = L"";
	std::wstring _path = L"";
	int _customPort = 0;

	std::string _authToken = "";

	std::mutex _mutex;
};

