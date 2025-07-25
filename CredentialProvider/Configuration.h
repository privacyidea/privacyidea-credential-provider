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
#include "PIConfig.h"
#include "PIResponse.h"
#include "Mode.h"
#include <credentialprovider.h>

class Configuration
{
public:
	void Load();

	void LogConfig();

	std::string ValidateAcceptLanguage(std::wstring configEntry);

	PIConfig piconfig;

	template<typename... Modes>
	bool ModeOneOf(Modes... modes) const noexcept
	{
		return ((mode == modes) || ...);
	}

	inline std::string ModeToString(Mode m)
	{
		switch (m)
		{
			case Mode::NO_CHANGE:						return "NO_CHANGE";
			case Mode::CHANGE_PASSWORD:					return "CHANGE_PASSWORD";
			case Mode::USERNAME:						return "USERNAME";
			case Mode::PASSWORD:						return "PASSWORD";
			case Mode::USERNAMEPASSWORD:				return "USERNAMEPASSWORD";
			case Mode::PRIVACYIDEA:						return "PRIVACYIDEA";
			case Mode::SEC_KEY_ANY:						return "SEC_KEY_ANY";
			case Mode::PASSKEY:							return "PASSKEY";
			case Mode::SEC_KEY_REG:						return "SEC_KEY_REG";
			case Mode::SEC_KEY_REG_PIN:					return "SEC_KEY_REG_PIN";
			case Mode::SEC_KEY_PIN:						return "SEC_KEY_PIN";
			case Mode::SEC_KEY_NO_PIN:					return "SEC_KEY_NO_PIN";
			case Mode::SEC_KEY_NO_DEVICE:				return "SEC_KEY_NO_DEVICE";
			default:									return "UNKNOWN_MODE";
		}
	}

	bool isCredentialComplete() const noexcept
	{
		return !credential.username.empty() && !credential.password.empty() && !credential.domain.empty();
	}

	inline std::string ModeString()
	{
		return ModeToString(mode);
	}

	bool isNextModePassword() const noexcept
	{
		return (mode != Mode::PASSWORD && mode != Mode::USERNAMEPASSWORD)
			&& !(twoStepSendPassword || usernamePassword);
	}

	bool isPasswordInFirstStep() const noexcept
	{
		return twoStepSendPassword || usernamePassword;
	}

	bool isFirstStep() const noexcept
	{
		return mode == Mode::USERNAME || mode == Mode::USERNAMEPASSWORD || mode == Mode::NO_CHANGE;
	}

	Mode GetFirstStepMode() const noexcept
	{
		if (twoStepSendPassword || usernamePassword)
		{
			return Mode::USERNAMEPASSWORD;
		}
		return Mode::USERNAME;
	}

	// FIDO2
	bool usePasskey = false;		// Online
	bool useOfflineFIDO = false;	// Offline
	bool disablePasskey = false;

	std::wstring bitmapPath = L"";

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
	bool hideFirstStepResponseError = false;
	bool noDefault = false;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	bool pushAuthenticationSuccess = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	std::optional<PIResponse> lastResponse;
	std::string lastTransactionId = "";

	std::wstring excludedAccount = L"";
	std::wstring excludedGroup = L"";
	std::wstring exludedGroupNetBIOSaddress = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	int offlineTreshold = 20;
	bool offlineShowInfo = true;
	bool creduiNoImage = false;

	bool webAuthnPreferred = false;
	bool webAuthnOfflineNoPIN = false;

	bool otpFailReturnToFirstStep = false;

	// Track the current state
	Mode mode = Mode::NO_CHANGE;

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
