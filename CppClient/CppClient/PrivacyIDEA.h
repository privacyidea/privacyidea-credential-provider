/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
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
#include "FIDOSignResponse.h"
#include "FIDORegistrationResponse.h"
#include <Windows.h>
#include <map>
#include <functional>
#include <atomic>
#include <optional>

constexpr auto PI_ENDPOINT_VALIDATE_CHECK = "/validate/check";
constexpr auto PI_ENDPOINT_POLLTRANSACTION = "/validate/polltransaction";
constexpr auto PI_ENDPOINT_OFFLINE_REFILL = "/validate/offlinerefill";
constexpr auto PI_ENDPOINT_VALIDATE_INITIALIZE = "/validate/initialize";

#define PI_ERROR_WRONG_PARAMETER					((HRESULT)0x88809011)

constexpr auto PI_ERR_AUTH_FAILED = 0x88809099;

class PrivacyIDEA
{
public:
	PrivacyIDEA(const PIConfig& config) :
		_config(config),
		_endpoint(config),
		offlineHandler(config.offlineFilePath, config.offlineTryWindow)
	{};

	PrivacyIDEA& operator=(const PrivacyIDEA& privacyIDEA) = delete;

	/// <summary>
	/// Authenticate using the /validate/check endpoint. The server response is written to responseObj.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="domain"></param>
	/// <param name="otp"></param>
	/// <param name="responseObj">This will be filled with the response of the server if no error occurred.</param>
	/// <param name="transaction_id">Optional to reference a challenge that was triggered before. If this is empty, it will not be send.</param>
	/// <param name="upn">Optional UPN to use instead of username. If this is set, it will be send as is instead of the username+domain.</param>
	/// <returns>S_OK if the request was processed correctly. Possible error codes: PI_ERROR_ENDPOINT_SETUP, PI_ERROR_SERVER_UNAVAILABLE, PI_JSON_PARSE_ERROR</returns>
	HRESULT ValidateCheck(
		const std::wstring& username,
		const std::wstring& domain,
		const std::wstring& otp,
		PIResponse& responseObj,
		const std::string& transactionId = std::string(),
		const std::wstring& upn = std::wstring(),
		const std::map<std::string, std::string>& headers = std::map<std::string, std::string>());

	/// <summary>
	/// Authenticate with WebAuthn using the /validate/check endpoint. The server response is written to responseObj.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="domain"></param>
	/// <param name="webAuthnSignResponse"></param>
	/// <param name="origin"></param>
	/// <param name="responseObj">This will be filled with the response of the server if no error occurred</param>
	/// <param name="transaction_id">Required for this function. WebAuthn is always challenge-response</param>
	/// <returns>S_OK if the request was processed correctly. Possible error codes: PI_ERROR_ENDPOINT_SETUP, PI_ERROR_SERVER_UNAVAILABLE, PI_JSON_PARSE_ERROR</returns>
	HRESULT ValidateCheckFIDO(const std::wstring& username,
		const std::wstring& domain, const FIDOSignResponse & fidoSignResponse,
		const std::string& origin,
		PIResponse& response,
		const std::string& transactionId,
		const std::wstring& upn = std::wstring());

	/// <summary>
	/// 
	/// </summary>
	/// <param name="transactionId"></param>
	/// <param name="serial"></param>
	/// <param name="username"></param>
	/// <param name="registrationResponse"></param>
	/// <param name="origin"></param>
	/// <returns></returns>
	HRESULT ValidateCheckCompletePasskeyRegistration(
		const std::string& transactionId,
		const std::string& serial,
		const std::wstring& username,
		const std::wstring& domain,
		FIDORegistrationResponse registrationResponse,
		const std::string& origin,
		PIResponse& piresponse);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="type"></param>
	/// <param name="response"></param>
	/// <returns></returns>
	HRESULT ValidateInitialize(PIResponse& response, const std::string & type = "passkey");

	/// <summary>
	/// Try to validate the given OTP value with the offline data for the user.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="otp"></param>
	/// <returns>S_OK, E_FAIL, PI_OFFLINE_DATA_NO_OTPS_LEFT, PI_OFFLINE_NO_OFFLINE_DATA</returns>
	HRESULT OfflineCheck(const std::wstring& username, const std::wstring& otp, __out std::string& serialUsed);

	/// <summary>
	/// Try to refill offline OTP values with a request to /validate/offlinerefill.
	/// </summary>
	/// <param name="username"></param>
	/// <param name="lastOTP"></param>
	/// <returns>S_OK, E_FAIL, PI_JSON_PARSE_ERROR, PI_ERROR_ENDPOINT_SETUP, PI_ERROR_SERVER_UNAVAILABLE</returns>
	HRESULT OfflineRefill(const std::wstring& username, const std::wstring& lastOTP, const std::string& serial);

	HRESULT OfflineRefillFIDO(const std::wstring& username, const std::string& serial);

	bool StopPoll();

	//
	// Poll for the given transaction asynchronously. When polling returns success, the transaction is finalized automatically
	// according to https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	// After that, the callback function is called with the result
	//
	void PollTransactionAsync(std::wstring username, std::wstring domain, std::wstring upn, std::string transactionId,
		std::function<void(const PIResponse&)> callback);

	//
	// Poll for a transaction_id. If this returns success, the transaction must be finalized by calling validate/check with the username, transaction_id and an EMPTY pass parameter.
	// https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	//
	bool PollTransaction(std::string transactionId);

	OfflineHandler offlineHandler;


	/// <summary>
	/// Return an offline FIDO2 sign request if offline FIDO2 token data is available. For every token, the credential_id will be in
	/// allowed_credential
	/// </summary>
	/// <returns>std::optional<FIDO2SignRequest></returns>
	std::optional<FIDOSignRequest> GetOfflineFIDOSignRequest();
	
private:
	HRESULT AppendRealm(std::wstring domain, std::map<std::string, std::string>& parameters);

	std::string SendRequestWithFallback(
		const std::string& endpoint,
		const std::map<std::string, std::string>& parameters,
		const std::map<std::string, std::string>& headers,
		RequestMethod method);

	HRESULT EvaluateResponse(std::string response, _Inout_ PIResponse& responseObj);

	void PollThread(const std::wstring& username, const std::wstring& domain, const std::wstring& upn, const std::string& transactionId, 
		std::function<void(const PIResponse&)> callback);

	Endpoint _endpoint;
	PIConfig _config;

	std::atomic<bool> _runPoll = false;
	JsonParser _parser;
};

