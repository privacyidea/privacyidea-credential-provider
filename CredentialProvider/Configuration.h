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

enum class SCENARIO
{
	NO_CHANGE = 0,
	LOGON_BASE = 1,
	UNLOCK_BASE = 2,
	SECOND_STEP = 3,
	LOGON_TWO_STEP = 4,
	UNLOCK_TWO_STEP = 5,
	CHANGE_PASSWORD = 6,

	SECURITY_KEY_ANY = 20,
	SECURITY_KEY_PIN = 21,
	SECURITY_KEY_NO_PIN = 22, // Requires reset with autoLogon to get to CCredential::Connect directly
	SECURITY_KEY_NO_DEVICE = 23, // Requires reset with autoLogon to get to CCredential::Connect directly
};

class Configuration
{
public:
	void Load();

	void LogConfig();

	bool IsSecondStep() const noexcept;

	PIConfig piconfig;

	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
	std::wstring otpFailureText = L"";
	std::wstring useOtpLinkText;
	std::wstring bitmapPath = L"";

	bool twoStepHideOTP = false;
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;

	bool hideFullName = false;
	bool hideDomainName = false;

	bool showDomainHint = false;
	bool prefillUsername = false;

	bool showResetLink = false;
	std::wstring resetLinkText = L"";

	bool debugLog = false;
	
	bool noDefault = false;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	bool pushAuthenticationSuccessful = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	PIResponse lastResponse;
	std::string lastTransactionId = "";

	std::wstring excludedAccount = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	int offlineTreshold = 20;
	bool offlineShowInfo = true;

	std::wstring webAuthnLinkText;
	std::wstring webAuthnPinHint;
	bool webAuthnPreferred = false;
	bool otpFailReturnToFirstStep = false;

	// Track the current state
	SCENARIO scenario = SCENARIO::NO_CHANGE;

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
		std::wstring upn = L"";
		std::wstring webAuthnPIN = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;

		std::wstring newPassword1 = L"";
		std::wstring newPassword2 = L"";
	} credential;
};
