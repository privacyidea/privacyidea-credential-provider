#include "general.h"
#include "Configuration.h"
#include "Logger.h"

using namespace std;

namespace General
{

	namespace Logon
	{

		HRESULT KerberosLogon(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
		)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr;

			WCHAR wsz[MAX_SIZE_DOMAIN];
			DWORD cch = ARRAYSIZE(wsz);
			BOOL  bGetCompName = false;

			if (EMPTY(domain))
				bGetCompName = GetComputerNameW(wsz, &cch);

			if (bGetCompName)
				domain = wsz;
#ifdef _DEBUG
			DebugPrintLn("Credential:");
			DebugPrintLn(username);
			if (Configuration::Get().logSensitive) {
				DebugPrintLn(password);
			}

			DebugPrintLn(domain);
#endif
			if (domain != NULL || bGetCompName)
			{
				PWSTR pwzProtectedPassword;

				hr = ProtectIfNecessaryAndCopyPassword(password, cpus, &pwzProtectedPassword);

				if (SUCCEEDED(hr))
				{
					KERB_INTERACTIVE_UNLOCK_LOGON kiul;

					// Initialize kiul with weak references to our credential.
					hr = KerbInteractiveUnlockLogonInit(domain, username, pwzProtectedPassword, cpus, &kiul);

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

		HRESULT KerberosChangePassword(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
			__in PWSTR username,
			__in PWSTR password_old,
			__in PWSTR password_new,
			__in PWSTR domain
		)
		{
			DebugPrintLn(__FUNCTION__);
			KERB_CHANGEPASSWORD_REQUEST kcpr;
			ZeroMemory(&kcpr, sizeof(kcpr));

			HRESULT hr;

			WCHAR wsz[64];
			DWORD cch = ARRAYSIZE(wsz);
			BOOL  bGetCompName = true;

			if (!EMPTY(domain))
				wcscpy_s(wsz, ARRAYSIZE(wsz), domain);
			else
				bGetCompName = GetComputerNameW(wsz, &cch);

			DebugPrintLn(username);
			DebugPrintLn(wsz);
			//DebugPrintLn(password_old);
			//DebugPrintLn(password_new);

			if (domain != NULL || bGetCompName)
			{
				hr = UnicodeStringInitWithString(wsz, &kcpr.DomainName);
				if (SUCCEEDED(hr))
				{
					hr = UnicodeStringInitWithString(username, &kcpr.AccountName);
					if (SUCCEEDED(hr))
					{
						hr = UnicodeStringInitWithString(password_old, &kcpr.OldPassword);
						hr = UnicodeStringInitWithString(password_new, &kcpr.NewPassword);
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

		HRESULT CredPackAuthentication(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
		)
		{
#ifdef _DEBUG
			DebugPrintLn(__FUNCTION__);
			DebugPrintLn(username);
			if (Configuration::Get().logSensitive) {
				DebugPrintLn(password);
			}
			DebugPrintLn(domain);
#endif
			PWSTR pwzProtectedPassword;
			HRESULT hr = ProtectIfNecessaryAndCopyPassword(password, cpus, &pwzProtectedPassword);

			WCHAR wsz[MAX_SIZE_DOMAIN];
			DWORD cch = ARRAYSIZE(wsz);
			BOOL  bGetCompName = false;

			if (EMPTY(domain))
				bGetCompName = GetComputerNameW(wsz, &cch);

			if (bGetCompName)
				domain = wsz;

			if (SUCCEEDED(hr))
			{
				PWSTR domainUsername = NULL;
				hr = DomainUsernameStringAlloc(domain, username, &domainUsername);
				DebugPrintLn(domainUsername);
				if (SUCCEEDED(hr))
				{
					DWORD size = 0;
					BYTE* rawbits = NULL;

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
						domainUsername, password, rawbits, &size))
					{
						// We received the necessary size, let's allocate some rawbits
						if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
						{
							rawbits = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);

							if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
								domainUsername, password, rawbits, &size))
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

							// At self point the credential has created the serialized credential used for logon
							// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
							// that we have all the information we need and it should attempt to submit the 
							// serialized credential.
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}

				CoTaskMemFree(pwzProtectedPassword);
			}

			return hr;
		}

	} // Namespace Logon

	namespace Fields
	{

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
		)
		{
			SetScenario(self, pCPCE, SCENARIO_NO_CHANGE, large_text, small_text);
		}

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario
		)
		{
			SetScenario(self, pCPCE, scenario, NULL, NULL);
		}

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
		)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;
			hr = Helpers::SetScenarioBasedFieldStates(self, pCPCE, scenario);


			int hide_fullname = Configuration::Get().hideFullName;

			// Set text fields separately
			int largeTextFieldId = 0, smallTextFieldId = 0;

			hr = Helpers::SetScenarioBasedTextFields(largeTextFieldId, smallTextFieldId, Data::Provider::Get()->usage_scenario);

			if (large_text)
			{
				DebugPrintLn("Large Text:");
				DebugPrintLn(large_text);
				pCPCE->SetFieldString(self, largeTextFieldId, large_text);
			}

			if (small_text && !hide_fullname)
			{
				DebugPrintLn("Small Text:");
				DebugPrintLn(small_text);
				pCPCE->SetFieldString(self, smallTextFieldId, small_text);
				//pCPCE->SetFieldState(self, smallTextFieldId, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else if (hide_fullname) {
				DebugPrintLn("Small Text: hide username");
				DebugPrintLn(small_text);
				pCPCE->SetFieldString(self, smallTextFieldId, L"");
			}
			else
			{
				DebugPrintLn("Small Text: Empty");
				pCPCE->SetFieldString(self, smallTextFieldId, L"");
				pCPCE->SetFieldState(self, smallTextFieldId, CPFS_HIDDEN);
			}

			if (!EMPTY(Data::Credential::Get()->message) && !EMPTY(Data::Credential::Get()->tx_id))
			{
				DebugPrintLn("Challenge-Response message found, setting it to smalltext:");
				wchar_t tmp[256];
				size_t length = strlen(Data::Credential::Get()->message);
				mbstowcs_s(&length, tmp, Data::Credential::Get()->message, length);
				DebugPrintLn(tmp);
				pCPCE->SetFieldString(self, smallTextFieldId, tmp);
				pCPCE->SetFieldState(self, smallTextFieldId, CPFS_DISPLAY_IN_BOTH);
			}

		}

		HRESULT SetFieldStatePairBatch(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in const FIELD_STATE_PAIR* pFSP
		) {
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;

			if (!pCPCE || !pFSP)
				return E_INVALIDARG;

			for (unsigned int i = 0; i < GetCurrentNumFields() && SUCCEEDED(hr); i++)
			{
				hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);

				if (SUCCEEDED(hr))
					hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
			}

			return hr;
		}

		HRESULT Clear(wchar_t* (&field_strings)[MAX_NUM_FIELDS], CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[MAX_NUM_FIELDS],
			ICredentialProviderCredential* pcpc, ICredentialProviderCredentialEvents* pcpce, char clear)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;

			for (unsigned int i = 0; i < GetCurrentNumFields() && SUCCEEDED(hr); i++)
			{
				char do_something = 0;

				if ((pcpfd[i].cpft == CPFT_PASSWORD_TEXT && clear >= CLEAR_FIELDS_CRYPT) || (pcpfd[i].cpft == CPFT_EDIT_TEXT && clear >= CLEAR_FIELDS_EDIT_AND_CRYPT))
				{
					if (field_strings[i])
					{
						// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
						size_t len = lstrlen(field_strings[i]);
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

		unsigned int GetCurrentNumFields()
		{
			//DebugPrintLn(__FUNCTION__);

			if (Data::Provider::Get() != NULL)
			{
				return  s_rgCredProvNumFieldsFor[Data::Provider::Get()->usage_scenario];

			}

			return 0;
		}

#pragma warning( disable : 4456 )
		HRESULT InitializeField(LPWSTR* rgFieldStrings, const FIELD_INITIALIZOR initializer, DWORD field_index)
		{
			HRESULT hr = E_INVALIDARG;
			int hide_fullname = Configuration::Get().hideFullName;
			int hide_domainname = Configuration::Get().hideDomainName;

			wstring loginText = Configuration::Get().loginText;

			switch (initializer.type)
			{
			case FIT_VALUE:
				//DebugPrintLn("...FIT_VALUE");
				hr = SHStrDupW(initializer.value, &rgFieldStrings[field_index]);
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_USERNAME:
				//DebugPrintLn("...FIT_USERNAME");
				if (NOT_EMPTY(Data::Credential::Get()->user_name) && !hide_fullname)
					hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				else
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_USERNAME_AND_DOMAIN:
				//DebugPrintLn("...FIT_USERNAME_AND_DOMAIN");
				if (NOT_EMPTY(Data::Credential::Get()->user_name) && NOT_EMPTY(Data::Credential::Get()->domain_name)
					&& !hide_fullname && !hide_domainname)
				{

					wstring fullName = wstring(Data::Credential::Get()->user_name) + L"@" + wstring(Data::Credential::Get()->domain_name);

					hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
				}
				else if (NOT_EMPTY(Data::Credential::Get()->user_name) && hide_domainname)
				{
					hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				}
				else
				{
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				}
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_LOGIN_TEXT:
				hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_VALUE_OR_LOGIN_TEXT:
				//DebugPrintLn("...FIT_VALUE_OR_LOGIN_TEXT");
				// This is the USERNAME field which is displayed in the list of users to the right
				if (!loginText.empty())
				{
					hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
				}
				else if (hide_fullname)
				{
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				}
				else
				{
					wstring initValue(initializer.value);
					// TODO initializer value is always empty for the user field?
					if (initValue.empty()) {
						// Provide default value
						hr = SHStrDupW(L"privacyIDEA Login", &rgFieldStrings[field_index]);
					}
					else 
					{
						hr = SHStrDupW(initializer.value, &rgFieldStrings[field_index]);
					}
				}
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_VALUE_OR_LOCKED_TEXT:
				//DebugPrintLn("...FIT_VALUE_OR_LOCKED_TEXT");
				//if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION && NOT_EMPTY(WORKSTATION_LOCKED))
				if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION && NOT_EMPTY(Data::Credential::Get()->user_name)
					&& !hide_fullname && !hide_domainname)
				{
					//DebugPrintLn("......Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION");
					//hr = SHStrDupW(WORKSTATION_LOCKED, &rgFieldStrings[field_index]);
					if (NOT_EMPTY(Data::Credential::Get()->domain_name))
					{
						wstring fullName = wstring(Data::Credential::Get()->user_name) + L"@" + wstring(Data::Credential::Get()->domain_name);

						hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
					}
					else if (NOT_EMPTY(Data::Credential::Get()->user_name))
					{
						hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
					}
				}
				else if (NOT_EMPTY(Data::Credential::Get()->user_name) && hide_domainname && !hide_fullname)
				{
					hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				}
				else if (hide_fullname)
				{
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				}
				else
				{
					hr = SHStrDupW(initializer.value, &rgFieldStrings[field_index]);
				}
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_NONE:
				//DebugPrintLn("...FIT_NONE");
				break;
			default:
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				//DebugPrintLn("default:");
				//DebugPrintLn(rgFieldStrings[field_index]);
				break;
			}

			return hr;
		}

	} // Namespace Fields

} // Namespace General