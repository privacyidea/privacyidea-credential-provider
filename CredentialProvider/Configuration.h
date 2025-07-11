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

enum class MODE
{
	NO_CHANGE = 0,
	CHANGE_PASSWORD = 6,

	USERNAME = 10,
	PASSWORD = 11,
	USERNAMEPASSWORD = 12, // Required for send_pass.

	PRIVACYIDEA = 13,
	SECURITY_KEY_ANY = 15,
	PASSKEY = 16,

	SEC_KEY_REG = 17,
	SEC_KEY_REG_PIN = 18,

	SEC_KEY_PIN = 21,
	SEC_KEY_NO_PIN = 22, // Requires reset with autoLogon to get to CCredential::Connect directly
	SEC_KEY_NO_DEVICE = 23, // Requires reset with autoLogon to get to CCredential::Connect directly
};


class Configuration
{
public:
	void Load();

	void LogConfig();

	PIConfig piconfig;

	template<typename... Modes>
	bool ModeOneOf(Modes... modes) const noexcept
	{
		return ((mode == modes) || ...);
	}

	inline std::string ModeString()
	{
		switch (mode)
		{
			case MODE::NO_CHANGE:						return "NO_CHANGE";
			case MODE::CHANGE_PASSWORD:					return "CHANGE_PASSWORD";
			case MODE::USERNAME:						return "USERNAME";
			case MODE::PASSWORD:						return "PASSWORD";
			case MODE::USERNAMEPASSWORD:				return "USERNAMEPASSWORD";
			case MODE::PRIVACYIDEA:						return "PRIVACYIDEA";
			case MODE::PASSKEY:							return "PASSKEY";
			case MODE::SEC_KEY_REG:						return "SECURITY_KEY_REGISTRATION";
			case MODE::SEC_KEY_REG_PIN:					return "SECURITY_KEY_REGISTRATION_PIN";
			case MODE::SECURITY_KEY_ANY:				return "SECURITY_KEY_ANY";
			case MODE::SEC_KEY_PIN:						return "SECURITY_KEY_PIN";
			case MODE::SEC_KEY_NO_PIN:					return "SECURITY_KEY_NO_PIN";
			case MODE::SEC_KEY_NO_DEVICE:				return "SECURITY_KEY_NO_DEVICE";
			default:									return "UNKNOWN_MODE";
		}
	}

	bool isNextModePassword() const noexcept
	{
		return (mode != MODE::PASSWORD && mode != MODE::USERNAMEPASSWORD)
			&& !(twoStepSendPassword || usernamePassword);
	}

	bool isPasswordInFirstStep() const noexcept
	{
		return twoStepSendPassword || usernamePassword;
	}

	bool isLastStep() const noexcept
	{
		return mode == MODE::PASSWORD || (mode >= MODE::PRIVACYIDEA && isPasswordInFirstStep());
	}

	bool isFirstStep() const noexcept
	{
		return mode == MODE::USERNAME || mode == MODE::USERNAMEPASSWORD || mode == MODE::NO_CHANGE;
	}

	// FIDO2
	bool usePasskey = false;		// Online
	bool useOfflineFIDO2 = false;	// Offline
	bool disablePasskey = false;
	std::wstring usePasskeyText = L"";

	// Texts
	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
	std::wstring otpFailureText = L"";
	std::wstring useOtpLinkText;
	std::wstring bitmapPath = L"";
	std::wstring resetLinkText = L"";

	// Add locales files path
	std::wstring localesPath = L"";

	bool usernamePassword = false; // TODO add to installer
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;

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

	bool pushAuthenticationSuccess = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	PIResponse lastResponse; // TODO optional
	std::string lastTransactionId = "";

	std::wstring excludedAccount = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	int offlineTreshold = 20;
	bool offlineShowInfo = true;
	bool credui_no_image = false;

	std::wstring webAuthnLinkText;
	std::wstring webAuthnPinHint;
	bool webAuthnPreferred = false;
	bool webAuthnOfflineNoPIN = false;

	bool otpFailReturnToFirstStep = false;

	// Track the current state
	MODE mode = MODE::NO_CHANGE;

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
		std::wstring fido2PIN = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;

		std::wstring newPassword1 = L"";
		std::wstring newPassword2 = L"";
	} credential;
};
