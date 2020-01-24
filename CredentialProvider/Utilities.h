#pragma once
#include "Configuration.h"
#include "Logger.h"
#include "core/common.h"
#include "core/field_state_pair.h"
#include <memory>
#include <Windows.h>
#include <wincred.h>

#define CLEAR_FIELDS_CRYPT 0
#define CLEAR_FIELDS_EDIT_AND_CRYPT 1
#define CLEAR_FIELDS_ALL 2
#define CLEAR_FIELDS_ALL_DESTROY 3

#define MAX_SIZE_DOMAIN 64
#define MAX_SIZE_USERNAME 512

enum class SCENARIO
{
	NO_CHANGE = 0,
	LOGON_BASE = 1,
	UNLOCK_BASE = 2,
	SECOND_STEP = 3,
	LOGON_TWO_STEP = 4,
	UNLOCK_TWO_STEP = 5,
	CHANGE_PASSWORD = 6,
};

class Utilities
{
public:
	Utilities(std::shared_ptr<Configuration> c) noexcept;

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

	// Set all fields state depending on the scenario, then fill the fields depending on scenario and configuration
	HRESULT SetScenario(
		__in ICredentialProviderCredential * pCredential,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in SCENARIO scenario,
		__in std::wstring textForLargeField, 
		__in std::wstring textForSmallField
	);

	void SetScenario(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in SCENARIO scenario
	);

	HRESULT Clear(
		wchar_t* (&field_strings)[FID_NUM_FIELDS],
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
		ICredentialProviderCredential* pcpc,
		ICredentialProviderCredentialEvents* pcpce,
		char clear
	);

	HRESULT SetFieldStatePairBatch(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in const FIELD_STATE_PAIR* pFSP
	);

	HRESULT initializeField(
		LPWSTR* rgFieldStrings,
		const FIELD_INITIALIZOR initializer,
		DWORD field_index
	);

	void SeparateUserAndDomainName(
		__in wchar_t* domain_slash_username,
		__out wchar_t* username,
		__in int sizeUsername,
		__out_opt wchar_t* domain,
		__in_opt int sizeDomain
	);

	void WideCharToChar(__in PWSTR data, __in int buffSize, __out char* pc);

	void CharToWideChar(__in char* data, __in int buffSize, __out PWSTR pc);

	size_t Iso8859_1_to_utf8(char* content, size_t max_size);

	HRESULT ReadFieldValues();

	static const FIELD_STATE_PAIR* GetFieldStatePairFor(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, bool twoStepHideOTP);

	HRESULT Utilities::ResetScenario(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents);

private:
	std::shared_ptr<Configuration> _config;

	HRESULT ReadUserField();

	HRESULT ReadPasswordField();

	HRESULT ReadOTPField();
};

