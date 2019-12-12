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
#include "Endpoint.h"
#include "Challenge.h"
#include <list>
#include <string>
#include <credentialprovider.h>
#include <map>

// Token Type Available
enum class TTA
{
	NOT_SET,
	OTP,
	PUSH,
	BOTH
};

extern const std::wstring base_registry_path;
extern const std::wstring realm_registry_path;

class Configuration
{
public:
	Configuration(Configuration const&) = delete;
	void operator=(Configuration const&) = delete;

	static Configuration& Get()
	{
		static Configuration instance;
		return instance;
	}

	void printConfig();

	std::wstring loginText = L"";
	std::wstring otpText = L"";
	std::wstring bitmapPath = L"";
	std::wstring otpFailureText = L"";

	bool twoStepHideOTP = false;
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;
	bool isSecondStep = false;

	bool hideFullName = false;
	bool hideDomainName = false;

	bool releaseLog = false;
	bool logSensitive = false;

	bool noDefault = false;

	int hide_otp_sleep_s = 0;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	std::wstring default_realm = L"";

	std::map<std::wstring, std::wstring> realm_map = std::map<std::wstring, std::wstring>();

	bool use_offline = false;

	struct PROVIDER
	{
		ICredentialProviderEvents* _pCredentialProviderEvents = nullptr;
		UINT_PTR _upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO usage_scenario = CPUS_INVALID;
		DWORD credPackFlags = 0;

		// Possibly read-write
		CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr = nullptr;
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs = nullptr;
		PWSTR* status_text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;
		ICredentialProviderCredentialEvents* pCredProvCredentialEvents = nullptr;

		// Read-only
		ICredentialProviderCredential* pCredProvCredential = nullptr;
		wchar_t** field_strings = nullptr;
		int num_field_strings = 0;
	} provider;

	struct CREDENTIAL
	{
		std::wstring user_name = L"";
		std::wstring domain_name = L"";
		std::wstring password = L""; // TODO make pw wchar* to overwrite it
		std::wstring otp = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;
		bool use_offline_pass = false;

		// ChangePassword
		std::wstring newPassword1 = L"";
		std::wstring newPassword2 = L"";
	} credential;

	struct ENDPOINT
	{
		IQueryContinueWithStatus* pQueryContinueWithStatus = nullptr; // TODO remove? use only locally
		HRESULT status = ENDPOINT_STATUS_NOT_SET; // TODO remove, use member variable of endpoint instance
		bool userCanceled = false; // TODO remove, use status to indicate if needed

		std::wstring hostname = L"";
		std::wstring path = L"";
		int customPort = 0;
		bool sslIgnoreCA = false;
		bool sslIgnoreCN = false;
	} endpoint;

	struct CHALLENGERESPONSE
	{
		std::list<Challenge> challenges = std::list<Challenge>();
		bool usingPushToken = false; // TODO remove
		bool pushAuthenticationSuccessful = false;
		std::string transactionID = "";
		std::string serial = "";
		std::string message = "";

		TTA tta = TTA::NOT_SET;
	} challenge_response;

	struct GENERAL
	{
		bool bypassEndpoint = false;
		bool clearFields = true;
	} general;

private:
	Configuration();

	void loadMapping();

	std::wstring getRegistry(std::wstring name);

	bool getBoolRegistry(std::wstring name);

	int getIntRegistry(std::wstring name);
};