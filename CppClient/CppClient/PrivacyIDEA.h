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

#include "PIResponse.h"
#include "JsonParser.h"
#include "OfflineHandler.h"
#include "Logger.h"
#include "Endpoint.h"
#include "PIConfig.h"
#include <Windows.h>
#include <map>
#include <functional>
#include <atomic>

#define PI_ENDPOINT_VALIDATE_CHECK					"/validate/check"
#define PI_ENDPOINT_POLLTRANSACTION					"/validate/polltransaction"
#define PI_ENDPOINT_OFFLINE_REFILL					"/validate/offlinerefill"

class PrivacyIDEA
{
public:
	PrivacyIDEA(PIConfig conf) :
		_realmMap(conf.realmMap),
		_defaultRealm(conf.defaultRealm),
		_logPasswords(conf.logPasswords),
		_endpoint(conf),
		offlineHandler(conf.offlineFilePath, conf.offlineTryWindow)
	{};

	PrivacyIDEA& operator=(const PrivacyIDEA& privacyIDEA) = delete;

	/// <summary>
	/// Authenticate using the /validate/check endpoint. The server response is written to responseObj.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="domain"></param>
	/// <param name="otp"></param>
	/// <param name="responseObj">This will be filled with the response of the server if no error occurred</param>
	/// <param name="transaction_id">Optional to reference a challenge that was triggered before</param>
	/// <returns>S_OK if the request was processed correctly. Possible error codes: PI_ERROR_ENDPOINT_SETUP, PI_ERROR_SERVER_UNAVAILABLE, PI_JSON_PARSE_ERROR</returns>
	HRESULT ValidateCheck(const std::wstring& username, const std::wstring& domain, const std::wstring& otp, PIResponse& responseObj, const std::string& transaction_id = std::string());

	/// <summary>
	/// Try to validate the given OTP value with the offline data for the user.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="otp"></param>
	/// <returns>S_OK, E_FAIL, PI_OFFLINE_DATA_NO_OTPS_LEFT, PI_OFFLINE_NO_OFFLINE_DATA</returns>
	HRESULT OfflineCheck(const std::wstring& username, const std::wstring& otp);

	/// <summary>
	/// Try to refill offline OTP values with a request to /validate/offlinerefill.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="lastOTP"></param>
	/// <returns>S_OK, E_FAIL, PI_JSON_PARSE_ERROR, PI_ERROR_ENDPOINT_SETUP, PI_ERROR_SERVER_UNAVAILABLE</returns>
	HRESULT OfflineRefill(std::wstring username, std::wstring lastOTP);

	bool StopPoll();

	// Poll for the given transaction asynchronously. When polling returns success, the transaction is finalized automatically
	// according to https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	// After that, the callback function is called with the result
	void PollTransactionAsync(std::wstring username, std::wstring domain, std::string transaction_id, std::function<void(bool)> callback);

	// Poll for a transaction_id. If this returns success, the transaction must be finalized by calling validate/check with the username, transaction_id and an EMPTY pass parameter.
	// https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	bool PollTransaction(std::string transaction_id);

	OfflineHandler offlineHandler;

private:
	HRESULT AppendRealm(std::wstring domain, std::map<std::string, std::string>& parameters);

	void PollThread(const std::wstring& username, const std::wstring& domain, const std::string& transaction_id, std::function<void(bool)> callback);

	std::map<std::wstring, std::wstring> _realmMap;

	std::wstring _defaultRealm = L"";

	Endpoint _endpoint;
	
	bool _logPasswords = false;

	std::atomic<bool> _runPoll = false;

	JsonParser _parser;
};

