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
#include "PIConfig.h"
#include "PIResponse.h"
#include <credentialprovider.h>

class Configuration
{
public:
	void Load();

	void LogConfig();

	PIConfig piconfig;

	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
	std::wstring bitmapPath = L"";

	bool twoStepHideOTP = false;
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;
	bool isSecondStep = false;

	bool hideFullName = false;
	bool hideDomainName = false;

	bool showDomainHint = false;
	bool prefillUsername = false;
	bool showResetLink = false;

	bool debugLog = false;

	bool noDefault = false;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	bool pushAuthenticationSuccessful = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	bool userCanceled = false;

	PIResponse lastResponse;

	std::wstring defaultOTPFailureText = L"";
	std::wstring defaultOTPHintText = L"";

	std::wstring excludedAccount = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	int offlineTreshold = 20;
	bool showOfflineInfo = true;

	struct PROVIDER
	{
		ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
		UINT_PTR upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
		DWORD credPackFlags = 0;

		// Possibly read-write
		PWSTR* status_text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;

		// Read-only
		wchar_t** field_strings = nullptr;
	} provider;

	struct CREDENTIAL
	{
		std::wstring username = L"";
		std::wstring domain = L"";
		std::wstring password = L"";
		std::wstring otp = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;

		// ChangePassword
		std::wstring newPassword1 = L"";
		std::wstring newPassword2 = L"";
	} credential;
};
