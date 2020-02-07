#include "Utilities.h"
#include "helpers.h"
#include "SecureString.h"
#include <string>
#include <Shlwapi.h>
#include <codecvt>

using namespace std;

Utilities::Utilities(std::shared_ptr<Configuration> c) noexcept
{
	_config = c;
}

HRESULT Utilities::KerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr;

	WCHAR wsz[MAX_SIZE_DOMAIN]; // actually MAX_COMPUTERNAME_LENGTH + 1 would be enough
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
		bGetCompName = GetComputerNameW(wsz, &cch);

	if (bGetCompName)
		domain = wstring(wsz, cch);

#ifdef _DEBUG
	DebugPrint("Packing Credential:");
	DebugPrint(username);
	if (_config->logSensitive) {
		DebugPrint(password.c_str());
	}
	DebugPrint(domain);
#endif

	if (!domain.empty() || bGetCompName)
	{
		PWSTR pwzProtectedPassword;

		hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

		if (SUCCEEDED(hr))
		{
			KERB_INTERACTIVE_UNLOCK_LOGON kiul;
			LPWSTR lpwszDomain = new wchar_t[domain.size() + 1];
			wcscpy_s(lpwszDomain, (domain.size() + 1), domain.c_str());

			LPWSTR lpwszUsername = new wchar_t[username.size() + 1];
			wcscpy_s(lpwszUsername, (username.size() + 1), username.c_str());

			// Initialize kiul with weak references to our credential.
			hr = KerbInteractiveUnlockLogonInit(lpwszDomain, lpwszUsername, pwzProtectedPassword, cpus, &kiul);

			if (SUCCEEDED(hr))
			{
				// We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
				// KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
				// as necessary.
				hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

				if (SUCCEEDED(hr))
				{
					ULONG ulAuthPackage;
					hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

					if (SUCCEEDED(hr))
					{
						pcpcs->ulAuthenticationPackage = ulAuthPackage;
						pcpcs->clsidCredentialProvider = CLSID_CSample;
						//DebugPrintLn("Packing of KERB_INTERACTIVE_UNLOCK_LOGON successful");
						// At self point the credential has created the serialized credential used for logon
						// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
						// that we have all the information we need and it should attempt to submit the 
						// serialized credential.
						*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
					}
				}
			}

			delete[] lpwszDomain;
			delete[] lpwszUsername;

			CoTaskMemFree(pwzProtectedPassword);
		}
	}
	else
	{
		DWORD dwErr = GetLastError();
		hr = HRESULT_FROM_WIN32(dwErr);
	}

	return hr;
}

HRESULT Utilities::KerberosChangePassword(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in std::wstring username,
	__in SecureWString password_old,
	__in SecureWString password_new,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);
	KERB_CHANGEPASSWORD_REQUEST kcpr;
	ZeroMemory(&kcpr, sizeof(kcpr));

	HRESULT hr;

	WCHAR wsz[64];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (!domain.empty())
		wcscpy_s(wsz, ARRAYSIZE(wsz), domain.c_str());
	else
		bGetCompName = GetComputerNameW(wsz, &cch);

	DebugPrint(username);
	DebugPrint(wsz);
	//DebugPrintLn(password_old);
	//DebugPrintLn(password_new);

	if (!domain.empty() || bGetCompName)
	{
		hr = UnicodeStringInitWithString(wsz, &kcpr.DomainName);
		if (SUCCEEDED(hr))
		{
			PWSTR lpwszUsername = new wchar_t[(username.size() + 1)];
			wcscpy_s(lpwszUsername, (username.size() + 1), username.c_str());

			hr = UnicodeStringInitWithString(lpwszUsername, &kcpr.AccountName);
			if (SUCCEEDED(hr))
			{
				PWSTR lpwszPasswordOld = new wchar_t[(password_old.size() + 1)];
				wcscpy_s(lpwszPasswordOld, (password_old.size() + 1), password_old.c_str());

				PWSTR lpwszPasswordNew = new wchar_t[(password_new.size() + 1)];
				wcscpy_s(lpwszPasswordNew, (password_new.size() + 1), password_new.c_str());

				hr = UnicodeStringInitWithString(lpwszPasswordOld, &kcpr.OldPassword);
				hr = UnicodeStringInitWithString(lpwszPasswordNew, &kcpr.NewPassword);

				SecureZeroMemory(lpwszPasswordNew, sizeof(lpwszPasswordNew));
				SecureZeroMemory(lpwszPasswordOld, sizeof(lpwszPasswordOld));

				if (SUCCEEDED(hr))
				{
					kcpr.MessageType = KerbChangePasswordMessage;
					kcpr.Impersonating = FALSE;
					hr = KerbChangePasswordPack(kcpr, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;
						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
						if (SUCCEEDED(hr))
						{
							//DebugPrintLn("Packing KERB_CHANGEPASSWORD_REQUEST successful");
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CSample;
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}
			}
		}
	}
	else
	{
		DWORD dwErr = GetLastError();
		hr = HRESULT_FROM_WIN32(dwErr);
	}

	return hr;
}

HRESULT Utilities::CredPackAuthentication(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{

#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	DebugPrint(username);
	if (_config->logSensitive) {
		DebugPrint(password.c_str());
	}
	DebugPrint(domain);
#endif

	const DWORD credPackFlags = _config->provider.credPackFlags;
	PWSTR pwzProtectedPassword;
	HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
		bGetCompName = GetComputerNameW(wsz, &cch);

	if (bGetCompName)
		domain = wsz;

	if (SUCCEEDED(hr))
	{
		PWSTR domainUsername = NULL;
		hr = DomainUsernameStringAlloc(domain.c_str(), username.c_str(), &domainUsername);
		DebugPrint(domainUsername);
		if (SUCCEEDED(hr))
		{
			DWORD size = 0;
			BYTE* rawbits = NULL;

			LPWSTR lpwszPassword = new wchar_t[(password.size() + 1)];
			wcscpy_s(lpwszPassword, (password.size() + 1), password.c_str());

			if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
				domainUsername, lpwszPassword, rawbits, &size))
			{
				// We received the necessary size, let's allocate some rawbits
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					rawbits = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
						domainUsername, lpwszPassword, rawbits, &size))
					{
						HeapFree(GetProcessHeap(), 0, rawbits);
						HeapFree(GetProcessHeap(), 0, domainUsername);

						hr = HRESULT_FROM_WIN32(GetLastError());
					}
					else
					{
						pcpcs->rgbSerialization = rawbits;
						pcpcs->cbSerialization = size;
					}
				}
				else
				{
					HeapFree(GetProcessHeap(), 0, domainUsername);
					hr = HRESULT_FROM_WIN32(GetLastError());
				}
			}

			if (SUCCEEDED(hr))
			{
				ULONG ulAuthPackage;
				hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

				if (SUCCEEDED(hr))
				{
					pcpcs->ulAuthenticationPackage = ulAuthPackage;
					pcpcs->clsidCredentialProvider = CLSID_CSample;

					// At this point the credential has created the serialized credential used for logon
					// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
					// that we have all the information we need and it should attempt to submit the 
					// serialized credential.
					*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
				}
			}

			SecureZeroMemory(lpwszPassword, sizeof(lpwszPassword));
		}

		CoTaskMemFree(pwzProtectedPassword);
	}

	return hr;
}

HRESULT Utilities::SetScenario(
	__in ICredentialProviderCredential* pCredential,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in SCENARIO scenario)
{
	DebugPrint(__FUNCTION__);
	HRESULT hr = S_OK;

	switch (scenario)
	{
	case SCENARIO::LOGON_BASE:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioDisplayAllFields);
		break;
	case SCENARIO::UNLOCK_BASE:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioUnlockPasswordOTP);
		break;
	case SCENARIO::SECOND_STEP:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioSecondStepOTP);
		break;
	case SCENARIO::CHANGE_PASSWORD:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioPasswordChange);
		break;
	case SCENARIO::UNLOCK_TWO_STEP:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioUnlockFirstStepPassword);
		break;
	case SCENARIO::LOGON_TWO_STEP:
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioLogonFirstStepUserLDAP);
		break;
	case SCENARIO::NO_CHANGE:
	default:
		break;
	}

	const int hideFullName = _config->hideFullName;
	const int hideDomain = _config->hideDomainName;

	// Fill the textfields with text depending on configuration
	// Large text for username@domain, username or nothing
	// Small text for transaction message or default OTP message

	// Large text
	wstring text = _config->credential.username + L"@" + _config->credential.domain;
	if (hideDomain)
		text = _config->credential.username;
	if (hideFullName)
		text = L"";
	//DebugPrint(L"Setting large text: " + text);
	pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, text.c_str());
	if (text.empty())
		pCPCE->SetFieldState(pCredential, FID_LARGE_TEXT, CPFS_HIDDEN);

	// Small text, use if 1step or in 2nd step of 2step
	if (!_config->twoStepHideOTP || (_config->twoStepHideOTP && _config->isSecondStep))
	{
		if (!_config->challenge.message.empty())
		{
			//DebugPrint(L"Setting message of challenge to small text: " + _config->challenge.message);
			pCPCE->SetFieldString(pCredential, FID_SMALL_TEXT, _config->challenge.message.c_str());
			pCPCE->SetFieldState(pCredential, FID_SMALL_TEXT, CPFS_DISPLAY_IN_BOTH);
		}
		else
		{
			pCPCE->SetFieldString(pCredential, FID_SMALL_TEXT, _config->defaultOTPText.c_str());
		}
	}
	else
		pCPCE->SetFieldState(pCredential, FID_SMALL_TEXT, CPFS_HIDDEN);

	return hr;
}

HRESULT Utilities::Clear(
	wchar_t* (&field_strings)[FID_NUM_FIELDS],
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
	ICredentialProviderCredential* pcpc,
	ICredentialProviderCredentialEvents* pcpce,
	char clear)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		char do_something = 0;

		if ((pcpfd[i].cpft == CPFT_PASSWORD_TEXT && clear >= CLEAR_FIELDS_CRYPT) || (pcpfd[i].cpft == CPFT_EDIT_TEXT && clear >= CLEAR_FIELDS_EDIT_AND_CRYPT))
		{
			if (field_strings[i])
			{
				// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
				const size_t len = lstrlen(field_strings[i]);
				SecureZeroMemory(field_strings[i], len * sizeof(*field_strings[i]));

				do_something = 1;
			}
		}

		if (do_something || clear >= CLEAR_FIELDS_ALL)
		{
			CoTaskMemFree(field_strings[i]);
			hr = SHStrDupW(L"", &field_strings[i]);

			if (pcpce)
				pcpce->SetFieldString(pcpc, i, field_strings[i]);

			if (clear == CLEAR_FIELDS_ALL_DESTROY)
				CoTaskMemFree(pcpfd[i].pszLabel);
		}
	}

	return hr;
}

HRESULT Utilities::SetFieldStatePairBatch(
	__in ICredentialProviderCredential* self,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in const FIELD_STATE_PAIR* pFSP)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	if (!pCPCE || !self)
		return E_INVALIDARG;

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);

		if (SUCCEEDED(hr))
			hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
	}

	return hr;
}
// can be removed, SetScenario does the same
HRESULT Utilities::initializeField(
	LPWSTR* rgFieldStrings,
	DWORD field_index)
{
	HRESULT hr = E_INVALIDARG;
	const int hide_fullname = _config->hideFullName;
	const int hide_domainname = _config->hideDomainName;

	wstring loginText = _config->loginText;
	wstring user_name = _config->credential.username;
	wstring domain_name = _config->credential.domain;

	switch (field_index)
	{
	case FID_LDAP_PASS:
	case FID_PASS:
	case FID_SUBMIT_BUTTON:
	case FID_OFFLINE_CHECKBOX:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	case FID_USERNAME:
		if (!user_name.empty() && !domain_name.empty() && !hide_fullname && !hide_domainname)
		{
			wstring fullName = user_name + L"@" + domain_name;

			hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
		}
		else if (!user_name.empty() && hide_domainname)
		{
			hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		break;
	case FID_LARGE_TEXT:
		// This is the USERNAME field which is displayed in the list of users to the right
		if (!loginText.empty())
		{
			hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"privacyIDEA Login", &rgFieldStrings[field_index]);
		}
		break;
	case FID_SMALL_TEXT:
		// In CPUS_UNLOCK_WORKSTATION the username is already provided, therefore the field is disabled
		// and the name is displayed in this field instead (or hidden)
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && !user_name.empty()
			&& !hide_fullname && !hide_domainname)
		{
			if (!domain_name.empty())
			{
				wstring fullName = user_name + L"@" + domain_name;

				hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
			}
			else if (!user_name.empty())
			{
				hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
			}
			else
			{
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			}
		}
		else if (!user_name.empty() && hide_domainname && !hide_fullname)
		{
			hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
		}
		else if (hide_fullname)
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		break;
	case FID_LOGO:
		hr = S_OK;
		break;
	default:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	}
	//DebugPrintLn(rgFieldStrings[field_index]);
	return hr;
}

void Utilities::SeparateUserAndDomainName(
	__in wchar_t* fq_username,
	__out wchar_t* username,
	__in int sizeUsername,
	__out_opt wchar_t* domain,
	__in_opt int sizeDomain
)
{
	int pos;
	for (pos = 0; fq_username[pos] != L'\\' && fq_username[pos] != L'@' && fq_username[pos] != NULL; pos++);

	if (fq_username[pos] != NULL)
	{
		if (fq_username[pos] == L'\\')
		{
			int i;
			for (i = 0; i < pos && i < sizeDomain; i++)
				domain[i] = fq_username[i];
			domain[i] = L'\0';

			for (i = 0; fq_username[pos + i + 1] != NULL && i < sizeUsername; i++)
				username[i] = fq_username[pos + i + 1];
			username[i] = L'\0';
		}
		else
		{
			int i;
			for (i = 0; i < pos && i < sizeUsername; i++)
				username[i] = fq_username[i];
			username[i] = L'\0';

			for (i = 0; fq_username[pos + i + 1] != NULL && i < sizeDomain; i++)
				domain[i] = fq_username[pos + i + 1];
			domain[i] = L'\0';
		}
	}
	else
	{
		int i;
		for (i = 0; i < pos && i < sizeUsername; i++)
			username[i] = fq_username[i];
		username[i] = L'\0';
	}
}

void Utilities::WideCharToChar(__in PWSTR data, __in int buffSize, __out char* pc)
{
	WideCharToMultiByte(CP_ACP, 0, data, -1, pc, buffSize, NULL, NULL);
}

void Utilities::CharToWideChar(__in char* data, __in int buffSize, __out PWSTR pc)
{
	MultiByteToWideChar(CP_ACP, 0, data, -1, pc, buffSize);
}

size_t Utilities::Iso8859_1_to_utf8(char* content, size_t max_size)
{
	char* src, * dst;

	//first run to see if there's enough space for the new bytes
	for (src = dst = content; *src; src++, dst++)
	{
		if (*src & 0x80)
		{
			// If the high bit is set in the ISO-8859-1 representation, then
			// the UTF-8 representation requires two bytes (one more than usual).
			++dst;
		}
	}

	if (dst - content + 1 > (signed)max_size)
	{
		// Inform caller of the space required
		return dst - content + 1;
	}

	while (dst > src)
	{
		if (*src & 0x80)
		{
			*dst-- = 0x80 | (*src & 0x3f);                     // trailing byte
			*dst-- = 0xc0 | (*((unsigned char*)src--) >> 6);  // leading byte
		}
		else
		{
			*dst-- = *src--;
		}
	}
	return 0;  // SUCCESS
}

HRESULT Utilities::readFieldValues()
{
	DebugPrint(__FUNCTION__);
	//HRESULT ret = S_OK;
	switch (_config->provider.cpu)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		readUserField();
		readPasswordField();
		readOTPField();
		break;
	}
	return S_OK;
}

HRESULT Utilities::readUserField()
{
	DebugPrint(L"Loading username/domainname from GUI, raw: " + wstring(_config->provider.field_strings[FID_USERNAME]));

	wchar_t user_name[1024];
	wchar_t domain_name[1024];

	SeparateUserAndDomainName(_config->provider.field_strings[FID_USERNAME],
		user_name, sizeof(user_name) / sizeof(wchar_t),
		domain_name, sizeof(domain_name) / sizeof(wchar_t)
	);
	if (NOT_EMPTY(user_name))
	{
		_config->credential.username = wstring(user_name);
	}
	else
	{
		DebugPrint("Username is empty, keeping old value");
	}

	if (NOT_EMPTY(domain_name))
	{
		_config->credential.domain = wstring(domain_name);
	}
	else
	{
		DebugPrint("Domain is empty, keeping old value");
	}
	return S_OK;
}

HRESULT Utilities::readPasswordField()
{
	SecureWString newPassword(_config->provider.field_strings[FID_LDAP_PASS]);

	if (newPassword.empty())
	{
		DebugPrint("New password empty, keeping old value");
	}
	else
	{
		_config->credential.password = newPassword;
		DebugPrint(L"Loading password from GUI, value:");
		if (_config->logSensitive)
			DebugPrint(newPassword.c_str());
		else
		{
			if (newPassword.empty())
				DebugPrint("[Hidden] empty value");
			else
				DebugPrint("[Hidden] has value");
		}

	}
	return S_OK;
}

HRESULT Utilities::readOTPField()
{
	wstring newOTP(_config->provider.field_strings[FID_PASS]);
	if (newOTP.empty())
	{
		DebugPrint("new OTP empty, keeping old value");
	}
	else
	{
		_config->credential.otp = newOTP;
		DebugPrint(L"Loading OTP from GUI, value: " + newOTP);
	}
	return S_OK;
}

const FIELD_STATE_PAIR* Utilities::GetFieldStatePairFor(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, bool twoStepHideOTP)
{
	if (cpus == CPUS_UNLOCK_WORKSTATION)
	{
		return twoStepHideOTP ? s_rgScenarioUnlockFirstStepPassword : s_rgScenarioUnlockPasswordOTP;
	}
	else
	{
		return twoStepHideOTP ? s_rgScenarioLogonFirstStepUserLDAP : s_rgScenarioDisplayAllFields;
	}
}

HRESULT Utilities::ResetScenario(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents)
{
	DebugPrint(__FUNCTION__);
	/*PWSTR lpwszUsername = L"";
	if (!_config->credential.user_name.empty())
	{
		size_t len = (_config->credential.user_name.size() + 1);
		lpwszUsername = new wchar_t[len];
		wcscpy_s(lpwszUsername, len, _config->credential.user_name.c_str());
	} */

	if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
	{
		if (_config->twoStepHideOTP)
		{
			SetScenario(pSelf, pCredProvCredentialEvents,
				SCENARIO::UNLOCK_TWO_STEP);
		}
		else
		{
			SetScenario(pSelf, pCredProvCredentialEvents,
				SCENARIO::UNLOCK_BASE);
		}

	}
	else if (_config->provider.cpu == CPUS_LOGON)
	{
		if (_config->twoStepHideOTP)
		{
			SetScenario(pSelf, pCredProvCredentialEvents, SCENARIO::LOGON_TWO_STEP);
		}
		else
		{
			SetScenario(pSelf, pCredProvCredentialEvents, SCENARIO::LOGON_BASE);
		}
	}

	return S_OK;
}
