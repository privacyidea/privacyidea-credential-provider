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
#include "PIConf.h"
#include "Challenge.h"
#include <list>
#include <string>
#include <credentialprovider.h>
#include <map>

extern const std::wstring base_registry_path;
extern const std::wstring realm_registry_path;

class Configuration
{
public:
	Configuration();

	void printConfiguration();

	PICONFIG piconfig;

	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
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
	
	bool pushAuthenticationSuccessful = false;
	bool authenticationSuccessful = false;

	bool userCanceled = false;
	IQueryContinueWithStatus* pQueryContinueWithStatus = nullptr;

	Challenge challenge;

	std::wstring defaultChallengeText = L"Please confirm the authentication!";

	struct PROVIDER
	{
		ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
		UINT_PTR upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
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
	
	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	struct CREDENTIAL
	{
		std::wstring username = L"";
		std::wstring domain = L"";
		std::wstring password = L""; // TODO make pw wchar* to overwrite it
		std::wstring otp = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;
		bool use_offline_pass = false;

		// ChangePassword
		std::wstring newPassword1 = L"";
		std::wstring newPassword2 = L"";
	} credential;

	/*
	struct ENDPOINT
	{
		IQueryContinueWithStatus* pQueryContinueWithStatus = nullptr; // TODO remove? use only locally
		bool userCanceled = false; // TODO remove, use status to indicate if needed

		std::wstring hostname = L"";
		std::wstring path = L"";
		int customPort = 0;
		bool sslIgnoreCA = false;
		bool sslIgnoreCN = false;
	} endpoint;
	*/

private:

	bool loadRegistry();

	bool loadMapping();

	std::wstring getRegistry(std::wstring name);

	bool getBoolRegistry(std::wstring name);

	int getIntRegistry(std::wstring name);
};