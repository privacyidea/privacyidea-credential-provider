#include "general.h"

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

			DebugPrintLn("Credential:");
			DebugPrintLn(username);
			//DebugPrintLn(password);
			DebugPrintLn(domain);

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
			KERB_CHANGEPASSWORD_REQUEST kcpr;
			ZeroMemory(&kcpr, sizeof(kcpr));

			HRESULT hr;

			WCHAR wsz[64];
			DWORD cch = ARRAYSIZE(wsz);
			BOOL  bGetCompName = true;

			if (EMPTY(domain))
				wcscpy_s(wsz, ARRAYSIZE(wsz), domain);
			else
				bGetCompName = GetComputerNameW(wsz, &cch);

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
			DebugPrintLn(__FUNCTION__);

			PWSTR pwzProtectedPassword;
			HRESULT hr = ProtectIfNecessaryAndCopyPassword(password, cpus, &pwzProtectedPassword);

			if (SUCCEEDED(hr))
			{
				PWSTR domainUsername = NULL;
				hr = DomainUsernameStringAlloc(domain, username, &domainUsername);

				if (SUCCEEDED(hr))
				{
					DWORD size = 0;
					BYTE* rawbits = NULL;

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0, domainUsername, password, rawbits, &size))
					{
						// We received the necessary size, let's allocate some rawbits
						if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
						{
							rawbits = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);

							if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0, domainUsername, password, rawbits, &size))
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
			
			int hide_username = Configuration::Get()->hide_username;
			
			// Set text fields separately
			int largeTextFieldId = 0, smallTextFieldId = 0;
			hr = Helpers::SetScenarioBasedTextFields(largeTextFieldId, smallTextFieldId, Data::Provider::Get()->usage_scenario);

			if (large_text)
			{
				DebugPrintLn("Large Text:");
				DebugPrintLn(large_text);
				pCPCE->SetFieldString(self, largeTextFieldId, large_text);
			}

			if (small_text && !hide_username)
			{
				DebugPrintLn("Small Text:");
				DebugPrintLn(small_text);
				pCPCE->SetFieldString(self, smallTextFieldId, small_text);
				//pCPCE->SetFieldState(self, smallTextFieldId, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else if (hide_username) {
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

		HRESULT Clear(wchar_t* (&field_strings)[MAX_NUM_FIELDS], CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[MAX_NUM_FIELDS], ICredentialProviderCredential* pcpc, ICredentialProviderCredentialEvents* pcpce, char clear)
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

			int numFields = 0;

			if (Data::Provider::Get() != NULL)
			{
				/*
				switch (Data::Provider::Get()->usage_scenario)
				{
				case CPUS_LOGON:
				case CPUS_UNLOCK_WORKSTATION:
					numFields = LUFI_NUM_FIELDS;
					break;
				case CPUS_CHANGE_PASSWORD:
					numFields = CPFI_NUM_FIELDS;
					break;
				default:
					break;
				}
				*/

				numFields = s_rgCredProvNumFieldsFor[Data::Provider::Get()->usage_scenario];
			}

			//DebugPrintLn(numFields);

			return numFields;
		}

		#pragma warning( disable : 4456 )
		HRESULT InitializeField(LPWSTR *rgFieldStrings, const FIELD_INITIALIZOR initializor, DWORD field_index)
		{
			HRESULT hr = E_INVALIDARG;
			int hide_username = Configuration::Get()->hide_username; // hide user and domain
			switch (initializor.type)
			{
			case FIT_VALUE:
				DebugPrintLn("...FIT_VALUE");
				hr = SHStrDupW(initializor.value, &rgFieldStrings[field_index]);
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_USERNAME:
				DebugPrintLn("...FIT_USERNAME");
				if (NOT_EMPTY(Data::Credential::Get()->user_name) && !hide_username)
					hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				else
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_USERNAME_AND_DOMAIN:
				DebugPrintLn("...FIT_USERNAME_AND_DOMAIN");
				if (NOT_EMPTY(Data::Credential::Get()->user_name) && NOT_EMPTY(Data::Credential::Get()->domain_name) && !hide_username)
				{
					INIT_ZERO_WCHAR(username_domainname, 129);

					wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), Data::Credential::Get()->user_name);
					wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), L"@");
					wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), Data::Credential::Get()->domain_name);

					hr = SHStrDupW(username_domainname, &rgFieldStrings[field_index]);
				}
				else if (NOT_EMPTY(Data::Credential::Get()->user_name) && !hide_username)
					hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				else
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_LOGIN_TEXT:
				DebugPrintLn("...FIT_LOGIN_TEXT");
				wchar_t value[sizeof(Configuration::Get()->login_text)];
				Helper::CharToWideChar(Configuration::Get()->login_text, sizeof(Configuration::Get()->login_text), value);
				hr = SHStrDupW(value, &rgFieldStrings[field_index]);
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_VALUE_OR_LOGIN_TEXT:
				DebugPrintLn("...FIT_VALUE_OR_LOGIN_TEXT");
				if (NOT_EMPTY(Configuration::Get()->login_text))
				{
					DebugPrintLn("......Configuration::Get()->login_text");
					wchar_t value[sizeof(Configuration::Get()->login_text)];
					
					Helper::CharToWideChar(Configuration::Get()->login_text, sizeof(Configuration::Get()->login_text), value);
					//DebugPrintLn(value);
					hr = SHStrDupW(value, &rgFieldStrings[field_index]);
				}
				else if (hide_username) {
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				}
				else {
					hr = SHStrDupW(initializor.value, &rgFieldStrings[field_index]);
				}
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_VALUE_OR_LOCKED_TEXT:
				DebugPrintLn("...FIT_VALUE_OR_LOCKED_TEXT");
				//if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION && NOT_EMPTY(WORKSTATION_LOCKED))
				if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION && NOT_EMPTY(Data::Credential::Get()->user_name) && !hide_username)
				{
					DebugPrintLn("......Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION");
					//hr = SHStrDupW(WORKSTATION_LOCKED, &rgFieldStrings[field_index]);
					if (NOT_EMPTY(Data::Credential::Get()->domain_name))
					{
						INIT_ZERO_WCHAR(username_domainname, 129);

						wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), Data::Credential::Get()->user_name);
						wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), L"@");
						wcscat_s(username_domainname, sizeof(username_domainname) / sizeof(wchar_t), Data::Credential::Get()->domain_name);

						hr = SHStrDupW(username_domainname, &rgFieldStrings[field_index]);
					}
					else if (NOT_EMPTY(Data::Credential::Get()->user_name))
						hr = SHStrDupW(Data::Credential::Get()->user_name, &rgFieldStrings[field_index]);
				}
				else if (hide_username) {
					hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				}
				else
					hr = SHStrDupW(value, &rgFieldStrings[field_index]);
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			case FIT_NONE:
				DebugPrintLn("...FIT_NONE");
				break;
			default:
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
				DebugPrintLn("default:");
				DebugPrintLn(rgFieldStrings[field_index]);
				break;
			}

			return hr;
		}

	} // Namespace Fields

} // Namespace General