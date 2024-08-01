#include "Utilities.h"
#include "helpers.h"
#include "scenario.h"
#include "guid.h"
#include "PrivacyIDEA.h"
#include "Convert.h"
#include "Translator.h"
#include <stdexcept>
#include <Shlwapi.h>

using namespace std;

Utilities::Utilities(std::shared_ptr<Configuration> c) noexcept
{
	_config = c;
}

std::wstring Utilities::GetText(int id)
{
	// TODO if a new, configurable text is introduced, add it here
	switch (id)
	{
		case TEXT_WAN_PIN_HINT:
		{
			if (!_config->webAuthnPinHint.empty())
			{
				return _config->webAuthnPinHint;
			}
			break;
		}
		case TEXT_OTP_FIELD:
		{
			if (!_config->otpFieldText.empty())
			{
				return _config->otpFieldText;
			}
			break;
		}
		case TEXT_WRONG_OTP:
		{
			if (!_config->otpFailureText.empty())
			{
				return _config->otpFailureText;
			}
			break;
		}
		case TEXT_USE_WEBAUTHN:
		{
			if (!_config->webAuthnLinkText.empty())
			{
				return _config->webAuthnLinkText;
			}
			break;
		}
		case TEXT_USE_OTP:
		{
			if (!_config->useOtpLinkText.empty())
			{
				return _config->useOtpLinkText;
			}
			break;
		}
		case TEXT_RESET_LINK:
		{
			if (!_config->resetLinkText.empty())
			{
				return _config->resetLinkText;
			}
			break;
		}
		case TEXT_LOGIN_TEXT:
		{
			if (!_config->loginText.empty())
			{
				return _config->loginText;
			}
			break;
		}
		default:
		{
			break;
		}
	}
	// 
	// Translate text.
	try {
		// Get translated text by ID using the Translator instance
		return PITranslate(id);
	}
	catch (const std::out_of_range& oor) {
		UNREFERENCED_PARAMETER(oor);
		PIError("GetTranslatedText: No text for id: " + to_string(id));
		return L"";
	}
}

HRESULT Utilities::KerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in std::wstring password,
	__in std::wstring domain)
{
	PIDebug(string(__FUNCTION__) + " - Packing Credential with: ");

	HRESULT hr = S_OK;

	if (domain.empty())
	{
		PIDebug("Domain is empty, getting ComputerName");
		domain = Utilities::ComputerName();
	}

	PIDebug(L"Username: " + username);
	PIDebug(L"Password: " + (password.empty() ? L"empty password" :
		(_config->piconfig.logPasswords ? password : L"hidden but has value")));
	PIDebug(L"Domain: " + domain);

	if (!domain.empty())
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
		hr = HRESULT_FROM_WIN32(GetLastError());
	}

	return hr;
}

HRESULT Utilities::KerberosChangePassword(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in std::wstring username,
	__in std::wstring password_old,
	__in std::wstring password_new,
	__in std::wstring domain)
{
	PIDebug(__FUNCTION__);
	KERB_CHANGEPASSWORD_REQUEST kcpr;
	ZeroMemory(&kcpr, sizeof(kcpr));

	HRESULT hr = S_OK;

	WCHAR wsz[64];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (!domain.empty())
	{
		wcscpy_s(wsz, ARRAYSIZE(wsz), domain.c_str());
	}
	else
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}

	PIDebug(L"User: " + username);
	PIDebug(L"Domain: " + wstring(wsz));
	PIDebug(L"Pw old: " + (_config->piconfig.logPasswords ? password_old :
		(password_old.empty() ? L"no value" : L"hidden but has value")));
	PIDebug(L"Pw new: " + (_config->piconfig.logPasswords ? password_new :
		(password_new.empty() ? L"no value" : L"hidden but has value")));

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
				// These buffers cant be zeroed since they are passed to LSA
				PWSTR lpwszPasswordOld = new wchar_t[(password_old.size() + 1)];
				wcscpy_s(lpwszPasswordOld, (password_old.size() + 1), password_old.c_str());

				PWSTR lpwszPasswordNew = new wchar_t[(password_new.size() + 1)];
				wcscpy_s(lpwszPasswordNew, (password_new.size() + 1), password_new.c_str());
				// vvvv they just copy the pointer vvvv
				hr = UnicodeStringInitWithString(lpwszPasswordOld, &kcpr.OldPassword);
				hr = UnicodeStringInitWithString(lpwszPasswordNew, &kcpr.NewPassword);

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
		hr = HRESULT_FROM_WIN32(GetLastError());
	}

	return hr;
}

HRESULT Utilities::CredPackAuthentication(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in std::wstring password,
	__in std::wstring domain)
{

	PIDebug(__FUNCTION__);

	const DWORD credPackFlags = _config->provider.credPackFlags;
	PWSTR pwzProtectedPassword;
	HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
	{
		PIDebug("Domain is empty, getting ComputerName");
		bGetCompName = GetComputerNameW(wsz, &cch);
	}
	if (bGetCompName)
	{
		domain = wsz;
	}

	if (SUCCEEDED(hr))
	{
		PWSTR domainUsername = NULL;
		hr = DomainUsernameStringAlloc(domain.c_str(), username.c_str(), &domainUsername);

		if (SUCCEEDED(hr))
		{
			PIDebug(L"User and Domain:" + wstring(domainUsername));
			PIDebug(L"Password:");
			if (_config->piconfig.logPasswords)
			{
				PIDebug(password.c_str());
			}
			else
			{
				PIDebug("Logging of passwords is disabled.");
			}

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

HRESULT Utilities::Clear(
	wchar_t* (&field_strings)[FID_NUM_FIELDS],
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
	ICredentialProviderCredential* pcpc,
	ICredentialProviderCredentialEvents* pcpce,
	char clear)
{
	PIDebug(__FUNCTION__);

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
			{
				pcpce->SetFieldString(pcpc, i, field_strings[i]);
			}
			if (clear == CLEAR_FIELDS_ALL_DESTROY)
			{
				CoTaskMemFree(pcpfd[i].pszLabel);
			}
		}
	}

	return hr;
}

HRESULT Utilities::SetFieldStatePairBatch(
	__in ICredentialProviderCredential* self,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in const FIELD_STATE_PAIR* pFSP)
{
	PIDebug(__FUNCTION__);

	HRESULT hr = S_OK;

	if (!pCPCE || !self)
	{
		return E_INVALIDARG;
	}

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);

		if (SUCCEEDED(hr))
		{
			hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
		}
	}

	return hr;
}

HRESULT Utilities::InitializeField(
	LPWSTR rgFieldStrings[FID_NUM_FIELDS],
	DWORD field_index)
{
	HRESULT hr = E_INVALIDARG;
	const int hide_fullname = _config->hideFullName;
	const int hide_domainname = _config->hideDomainName;

	wstring loginText = _config->loginText;
	wstring user_name = _config->credential.username;
	wstring domain_name = _config->credential.domain;
	wstring text;

	switch (field_index)
	{
		case FID_NEW_PASS_1:
		case FID_NEW_PASS_2:
		case FID_OTP:
		case FID_SUBMIT_BUTTON:
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			break;
		}
		case FID_LDAP_PASS:
		{
			if (!_config->credential.password.empty())
			{
				hr = SHStrDupW(_config->credential.password.c_str(), &rgFieldStrings[field_index]);
			}
			else
			{
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			}
			break;
		}
		case FID_SUBTEXT:
		{
			if (_config->showDomainHint)
			{
				text = GetText(TEXT_DOMAIN_HINT) + _config->credential.domain;
			}
			hr = SHStrDupW(text.c_str(), &rgFieldStrings[field_index]);
			break;
		}
		case FID_USERNAME:
		{
			hr = SHStrDupW((user_name.empty() ? L"" : user_name.c_str()), &rgFieldStrings[field_index]);
			//PIDebug(L"Setting username: " + wstring(rgFieldStrings[field_index]));
			break;
		}
		case FID_LARGE_TEXT:
		{
			// This is the USERNAME field which is displayed in the list of users to the right
			if (!loginText.empty())
			{
				hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
			}
			else
			{
				hr = SHStrDupW(L"privacyIDEA Login", &rgFieldStrings[field_index]);
			}
			//PIDebug(L"Setting large text: " + wstring(rgFieldStrings[field_index]));
			break;
		}
		case FID_SMALL_TEXT:
		{
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
			//PIDebug(L"Setting small text: " + wstring(rgFieldStrings[field_index]));
			break;
		}
		case FID_LOGO:
		{
			hr = S_OK;
			break;
		}
		case FID_RESET_LINK:
		{
			hr = SHStrDupW(GetText(TEXT_RESET_LINK).c_str(), &rgFieldStrings[field_index]);
			break;
		}
		case FID_WAN_LINK:
		{
			hr = SHStrDupW(GetText(TEXT_USE_WEBAUTHN).c_str(), &rgFieldStrings[field_index]);
			break;
		}
		default:
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			break;
		}
	}
	return hr;
}

HRESULT Utilities::CopyInputFields()
{
	PIDebug(__FUNCTION__);
	switch (_config->provider.cpu)
	{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
		{
			if (!_config->credential.passwordMustChange)
			{
				CopyUsernameField();
				CopyPasswordField();
				CopyOTPField();
				CopyWANPinField();
			}
			else
			{
				CopyPasswordChangeFields();
			}
			break;
		}
	}

	return S_OK;
}

HRESULT Utilities::CopyPasswordChangeFields()
{
	_config->credential.password = _config->provider.field_strings[FID_LDAP_PASS];
	PIDebug(L"Old pw: " + _config->credential.password);
	_config->credential.newPassword1 = _config->provider.field_strings[FID_NEW_PASS_1];
	PIDebug(L"new pw1: " + _config->credential.newPassword1);
	_config->credential.newPassword2 = _config->provider.field_strings[FID_NEW_PASS_2];
	PIDebug(L"New pw2: " + _config->credential.newPassword2);
	return S_OK;
}

HRESULT Utilities::CopyUsernameField()
{
	wstring input;
	if (_config->provider.field_strings != nullptr)
	{
		input = wstring(_config->provider.field_strings[FID_USERNAME]);
	}

	PIDebug(L"Copying user and domain from GUI: '" + input + L"'");
	wstring username, domain;

	Utilities::SplitUserAndDomain(input, username, domain);

	if (Utilities::CheckForUPN(input))
	{
		_config->credential.upn = input;
	}

	if (!username.empty())
	{
		wstring newUsername(username);
		PIDebug(L"Changing user from '" + _config->credential.username + L"' to '" + newUsername + L"'");
		_config->credential.username = newUsername;
	}
	else
	{
		PIDebug(L"Username is empty, keeping old value: '" + _config->credential.username + L"'");
	}

	if (!domain.empty())
	{
		PIDebug(L"Changing domain from '" + _config->credential.domain + L"' to '" + domain + L"'");
		_config->credential.domain = domain;
	}
	else
	{
		PIDebug(L"Domain is empty, keeping old value: '" + _config->credential.domain + L"'");
	}

	return S_OK;
}

HRESULT Utilities::CopyPasswordField()
{
	std::wstring newPassword(_config->provider.field_strings[FID_LDAP_PASS]);

	if (newPassword.empty())
	{
		PIDebug("New password empty, keeping old value");
	}
	else
	{
		_config->credential.password = newPassword;

		PIDebug(L"Copying password from GUI, value:");
		if (_config->piconfig.logPasswords)
		{
			PIDebug(newPassword.c_str());
		}
		else
		{
			if (newPassword.empty())
			{
				PIDebug("[Hidden] empty value");
			}
			else
			{
				PIDebug("[Hidden] has value");
			}
		}
	}
	return S_OK;
}

HRESULT Utilities::CopyOTPField()
{
	wstring newOTP(_config->provider.field_strings[FID_OTP]);
	PIDebug(L"Loading OTP from GUI, from '" + _config->credential.otp + L"' to '" + newOTP + L"'");
	_config->credential.otp = newOTP;

	return S_OK;
}

HRESULT Utilities::CopyWANPinField()
{
	std::wstring pin(_config->provider.field_strings[FID_WAN_PIN]);
	if (pin.empty())
	{
		PIDebug("New PIN empty, keeping old value");
	}
	else
	{
		PIDebug(L"Copying PIN from GUI");
		_config->credential.webAuthnPIN = pin;
	}
	return S_OK;
}

std::wstring Utilities::ComputerName()
{
	wstring ret;
	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);

	const BOOL bGetCompName = GetComputerNameW(wsz, &cch);
	if (bGetCompName)
	{
		ret = wstring(wsz, cch);
	}
	else
	{
		PIDebug("Failed to retrieve computer name: " + to_string(GetLastError()));
	}
	return ret;
}

void Utilities::SplitUserAndDomain(const std::wstring& input, std::wstring& username, std::wstring& domain)
{
	auto pos = input.find(L'\\');
	if (pos == std::string::npos)
	{
		pos = input.find('@');
		if (pos != std::string::npos)
		{
			username = input.substr(0, pos);
			domain = input.substr(pos + 1, input.length());
		}
		else
		{
			// only user input, copy string
			username = wstring(input);
		}
	}
	else
	{
		// Actually split DOMAIN\USER
		username = wstring(input.substr(pos + 1, input.size()));
		domain = wstring(input.substr(0, pos));
	}

	if (domain == L".")
	{
		domain = Utilities::ComputerName();
	}
}

bool Utilities::CheckForUPN(const std::wstring& input)
{
	return input.find(L"@") != string::npos && input.find(L"\\") == string::npos;
}

