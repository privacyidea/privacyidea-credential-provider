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
constexpr auto TEXT_WAN_PIN_HINT = 14;
constexpr auto TEXT_TOUCH_SEC_KEY = 15;
constexpr auto TEXT_CONNECTING = 16;
constexpr auto TEXT_LOGIN_TEXT = 17;
constexpr auto TEXT_OTP_PROMPT = 18;
constexpr auto TEXT_FIDO_NO_CREDENTIALS = 19;
constexpr auto TEXT_FIDO_WAITING_FOR_DEVICE = 20;

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
		__in std::wstring password_old,
		__in std::wstring password_new,
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
		DWORD field_index
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
	static bool CheckForUPN(const std::wstring& input);
	
	HRESULT CopyInputFields();

	HRESULT CopyUsernameField();

	HRESULT CopyPasswordField();

	HRESULT CopyOTPField();

	HRESULT CopyWANPinField();

	HRESULT CopyPasswordChangeFields();

private:
	std::shared_ptr<Configuration> _config;
};

