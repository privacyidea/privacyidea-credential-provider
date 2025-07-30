#pragma once
#include "Configuration.h"
#include "Logger.h"
#include <scenario.h>
#include <memory>
#include <Windows.h>
#include <wincred.h>

constexpr auto CLEAR_FIELDS_CRYPT = 0;
constexpr auto CLEAR_FIELDS_EDIT_AND_CRYPT = 1;
constexpr auto CLEAR_FIELDS_ALL = 2;
constexpr auto CLEAR_FIELDS_ALL_DESTROY = 3;

constexpr auto MAX_SIZE_DOMAIN = 64;
constexpr auto MAX_SIZE_USERNAME = 512;

// Text IDs
constexpr auto TEXT_USERNAME = 0;
constexpr auto TEXT_PASSWORD = 1;
constexpr auto TEXT_OLD_PASSWORD = 2;
constexpr auto TEXT_NEW_PASSWORD = 3;
constexpr auto TEXT_CONFIRM_PASSWORD = 4;
constexpr auto TEXT_DOMAIN_HINT = 5;
constexpr auto TEXT_OTP_FIELD = 6;
constexpr auto TEXT_WRONG_OTP = 7;
constexpr auto TEXT_RESET_LINK = 8;
constexpr auto TEXT_AVAILABLE_OFFLINE_TOKEN = 9;
constexpr auto TEXT_OTPS_REMAINING = 10;
constexpr auto TEXT_GENERIC_ERROR = 11;
constexpr auto TEXT_USE_WEBAUTHN = 12;
constexpr auto TEXT_USE_OTP = 13;
constexpr auto TEXT_FIDO_PIN_HINT = 14;
constexpr auto TEXT_TOUCH_SEC_KEY = 15;
constexpr auto TEXT_CONNECTING = 16;
constexpr auto TEXT_LOGIN_TEXT = 17;
constexpr auto TEXT_OTP_PROMPT = 18;
constexpr auto TEXT_FIDO_NO_CREDENTIALS = 19;
constexpr auto TEXT_FIDO_WAITING_FOR_DEVICE = 20;
constexpr auto TEXT_FIDO_CHECKING_OFFLINE_STATUS = 21;
constexpr auto TEXT_OFFLINE_REFILL = 22;
constexpr auto TEXT_FIDO_ERR_PIN_BLOCKED = 23;
constexpr auto TEXT_FIDO_ERR_TX = 24;
constexpr auto TEXT_FIDO_ERR_PIN_INVALID = 25;
constexpr auto TEXT_USE_PASSKEY = 26;
constexpr auto TEXT_ENTER_USERNAME = 27;
constexpr auto TEXT_ENTER_PASSWORD = 28;
constexpr auto TEXT_ENTER_USERNAME_PASSWORD = 29;
constexpr auto TEXT_PASSKEY_REGISTER_TOUCH = 30;
constexpr auto TEXT_SEC_KEY_ENTER_PIN_PROMPT = 31;
constexpr auto TEXT_PASSKEY_REGISTRATION = 32;
constexpr auto TEXT_LOGIN_WITH_USERNAME = 33;
constexpr auto TEXT_FIDO_CANCELLED = 34;
constexpr auto TEXT_CANCEL_ENROLLMENT = 35;

class Utilities
{
public:
	Utilities(std::shared_ptr<Configuration> c) noexcept;
	
	/// <summary>
	/// If the text for the id is configurable and exists in the config, return that value.
	/// Otherwise, return the default text for the id in english or german, depending on GetUserDefaultUILanguage.
	/// </summary>
	/// <param name="id"></param>
	/// <returns></returns>
	std::wstring GetText(int id);

	HRESULT KerberosLogon(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in std::wstring password,
		__in std::wstring domain
	);

	HRESULT KerberosChangePassword(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__in std::wstring username,
		__in std::wstring passwordOld,
		__in std::wstring passwordNew,
		__in std::wstring domain
	);

	HRESULT CredPackAuthentication(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in std::wstring password,
		__in std::wstring domain
	);

	HRESULT Clear(
		wchar_t* (&field_strings)[FID_NUM_FIELDS],
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR (&pcpfd)[FID_NUM_FIELDS],
		ICredentialProviderCredential* pcpc,
		ICredentialProviderCredentialEvents* pcpce,
		char clear
	);

	HRESULT SetFieldStatePairBatch(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in const FIELD_STATE_PAIR* pFSP
	);

	HRESULT InitializeField(
		LPWSTR rgFieldStrings[FID_NUM_FIELDS],
		DWORD fieldIndex
	);

	static std::wstring ComputerName();

	/// <summary>
	/// Split the input into user and domain. The possible formats are: domain\user and user@domain, check in that order.
	/// If no '\' or '@' exsists in the input, the whole input is assumed to be the username.
	/// If the domain is '.', it will be resolved to the local computer name.
	/// </summary>
	/// <param name="input"></param>
	/// <param name="username"></param>
	/// <param name="domain"></param>
	static void SplitUserAndDomain(const std::wstring& input, std::wstring& username, std::wstring& domain);

	/// <summary>
	/// Check if the input is an UPN. The check is very basic and assumes the input is an UPN if it contains an @ and no \.
	/// </summary>
	/// <param name="input"></param>
	/// <param name="config"></param>
	/// <returns>bool if upn detected, false otherwise</returns>
	static bool CheckForUPN(const std::wstring& input) noexcept;
	
	HRESULT CopyInputFields();

	HRESULT CopyUsernameField();

	HRESULT CopyPasswordField();

	HRESULT CopyOTPField();

	HRESULT CopyWANPinField();

	HRESULT CopyPasswordChangeFields();

private:
	std::shared_ptr<Configuration> _config;
};

