/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**
** Author		Dominik Pretzsch
**				Nils Behlen
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
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "hooks.h"
#include "Logger.h"
#include "Configuration.h"
#include <Lmcons.h>

using namespace std;

namespace Hook
{
	namespace Serialization
	{
		auto& config = Configuration::Get();

		HRESULT ReadFieldValues()
		{
			DebugPrintLn(__FUNCTION__);
			HRESULT ret = S_OK;
			switch (Configuration::Get().provider.usage_scenario)
			{
			case CPUS_LOGON:
			case CPUS_UNLOCK_WORKSTATION:
			case CPUS_CREDUI:
				ReadUserField();
				ReadPasswordField();
				ReadOTPField();
				break;
			}
			return ret;
		}

		HRESULT ReadUserField()
		{
			DebugPrintLn(L"Loading username/domainname from GUI, raw: " + wstring(config.provider.field_strings[LUFI_OTP_USERNAME]));

			wchar_t user_name[1024];
			wchar_t domain_name[1024];

			Helper::SeparateUserAndDomainName(config.provider.field_strings[LUFI_OTP_USERNAME],
				user_name, sizeof(user_name) / sizeof(wchar_t),
				domain_name, sizeof(domain_name) / sizeof(wchar_t)
			);
			if (NOT_EMPTY(user_name))
			{
				Configuration::Get().credential.user_name = wstring(user_name);
			}
			else
			{
				DebugPrintLn("Username is empty, keeping old value");
			}

			if (NOT_EMPTY(domain_name))
			{
				Configuration::Get().credential.domain_name = wstring(domain_name);
			}
			else
			{
				DebugPrintLn("Domain is empty, keeping old value");
			}
			return S_OK;
		}

		HRESULT ReadPasswordField()
		{
			wstring newPassword(config.provider.field_strings[LUFI_OTP_LDAP_PASS]);
			//wchar_t password[1024];
			//wcscpy_s(password, sizeof(password) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_LDAP_PASS]);
			//Configuration::Get().credential.password = wstring(password);

			if (newPassword.empty())
			{
				DebugPrintLn("New password empty, keeping old value");
			}
			else
			{
				Configuration::Get().credential.password = newPassword;
				DebugPrintLn(L"Loading password from GUI, value: " + newPassword);
			}
			return S_OK;
		}

		HRESULT ReadOTPField()
		{
			wstring newOTP(config.provider.field_strings[LUFI_OTP_PASS]);
			//wchar_t otp[256];
			//wcscpy_s(otp, sizeof(otp) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_PASS]);
			//Configuration::Get().credential.otp = wstring(otp);
			if (newOTP.empty())
			{
				DebugPrintLn("new OTP empty, keeping old value");
			}
			else
			{
				Configuration::Get().credential.otp = newOTP;
				DebugPrintLn(L"Loading OTP from GUI, value: " + newOTP);
			}
			return S_OK;
		}

		HRESULT EndpointCallFailed()
		{
			DebugPrintLn(__FUNCTION__);

			//Endpoint::Get()->protectMe = false;

			INIT_ZERO_WCHAR(endpoint_error_msg, 150);
			INIT_ZERO_WCHAR(error_message, 150 + 100);

			//Endpoint::GetLastErrorDescription(endpoint_error_msg);

			//TODO
			swprintf_s(error_message, sizeof(error_message) / sizeof(wchar_t), L"An error occured. Error Code: %X\n\n%s", 345432, endpoint_error_msg);
			SHStrDupW(error_message, config.provider.status_text);

			*config.provider.status_icon = CPSI_ERROR;

			return S_OK;
		}

		HRESULT ChangePasswordSuccessfull()
		{
			DebugPrintLn(__FUNCTION__);

			if (Configuration::Get().credential.passwordMustChange)
			{
				Configuration::Get().credential.passwordChanged = true;
				Configuration::Get().general.clearFields = false;
				Configuration::Get().credential.passwordMustChange = false;
			}

			//SHStrDupW(L"Your password was successfully changed.", Hook::Serialization::Get()->status_text);

			*config.provider.pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
			*config.provider.status_icon = CPSI_SUCCESS;

			return S_OK;
		}

		HRESULT ChangePasswordFailed()
		{
			DebugPrintLn(__FUNCTION__);
			SHStrDupW(L"Your password could not be changed. Make sure you correctly typed your new password twice.",
				config.provider.status_text);

			*config.provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			*config.provider.status_icon = CPSI_ERROR;

			return S_OK;
		}

	} // Namespace Serialization

	namespace CredentialHooks
	{
		// switch passwordChanged and turn on AutoLogon
		HRESULT CheckPasswordChanging(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents, BOOL*& pbAutoLogon)
		{
			DebugPrintLn(__FUNCTION__);
			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			if (Configuration::Get().credential.passwordMustChange)
			{
				DebugPrintLn("CheckPasswordChanging TRUE");

				//General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_CHANGE_PASSWORD);
				//Configuration::Get().credential.passwordMustChange = false;
				return E_ABORT;
			}

			if (Configuration::Get().credential.passwordChanged) {
				//Configuration::Get().credential.passwordChanged = false;
				//Configuration::Get().general.bypassDataInitialization = true; // we dont want to initialize the kiul with the old password
				*pbAutoLogon = TRUE;
			}
			*pbAutoLogon = FALSE;
			return S_OK;
		}

		HRESULT ResetScenario(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents)
		{
			DebugPrintLn(__FUNCTION__);
			PWSTR username = L"";
			if (!Configuration::Get().credential.user_name.empty())
			{
				username = const_cast<PWSTR>(Configuration::Get().credential.user_name.c_str());
			}

			if (Configuration::Get().provider.usage_scenario == CPUS_UNLOCK_WORKSTATION)
			{
				if (Configuration::Get().twoStepHideOTP)
				{
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_TWO_STEP, NULL, username);
				}
				else
				{
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_BASE, NULL, username);
				}

			}
			else if (Configuration::Get().provider.usage_scenario == CPUS_LOGON)
			{
				if (Configuration::Get().twoStepHideOTP)
				{
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_LOGON_TWO_STEP);
				}
				else
				{
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_LOGON_BASE);
				}
			}

			return S_OK;
		}

		HRESULT GetSubmitButtonValue(DWORD dwFieldID, DWORD*& pdwAdjacentTo)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr;

			// Validate parameters.

			// !!!!!!!!!!!!!
			// !!!!!!!!!!!!!
			// TODO: Change scenario data structures to determine correct submit-button and pdwAdjacentTo dynamically

			if (LUFI_OTP_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
			{
				// pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
				*pdwAdjacentTo = LUFI_OTP_PASS;
				hr = S_OK;
			}
			else if (CPFI_OTP_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
			{
				*pdwAdjacentTo = CPFI_OTP_PASS_NEW_2;
				hr = S_OK;
			}
			else
			{
				hr = E_INVALIDARG;
			}

			return hr;
		}

		HRESULT GetComboBoxValueCount(DWORD dwFieldID, DWORD*& pcItems, DWORD*& pdwSelectedItem)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(dwFieldID);
			UNREFERENCED_PARAMETER(pcItems);
			UNREFERENCED_PARAMETER(pdwSelectedItem);

			HRESULT hr;

			*pcItems = 0; // ARRAYSIZE(s_rgLogonUnlockComboBoxModeStrings);
			*pdwSelectedItem = 0;
			hr = S_OK;

			return hr;
		}

		HRESULT GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR*& ppwszItem)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(dwFieldID);
			UNREFERENCED_PARAMETER(dwItem);
			UNREFERENCED_PARAMETER(ppwszItem);

			HRESULT hr;

			hr = E_INVALIDARG; //SHStrDupW(s_rgLogonUnlockComboBoxModeStrings[dwItem], ppwszItem);

			return hr;
		}

		HRESULT SetComboBoxSelectedValue(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents,
			DWORD dwFieldID, DWORD dwSelectedItem, DWORD& dwSelectedItemBuffer)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			UNREFERENCED_PARAMETER(dwFieldID);
			UNREFERENCED_PARAMETER(dwSelectedItem);
			UNREFERENCED_PARAMETER(dwSelectedItemBuffer);

			HRESULT hr;

			dwSelectedItemBuffer = dwSelectedItem;

			hr = S_OK;

			return hr;
		}

		HRESULT GetCheckboxValue(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents, wchar_t** rgFieldStrings,
			DWORD dwFieldID, BOOL*& pbChecked, PWSTR*& ppwszLabel)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			UNREFERENCED_PARAMETER(pbChecked);
			/*if (Data::Gui::Get() == NULL)
				Data::Gui::Init();

			*pbChecked = Data::Gui::Get()->use_offline_pass;*/
			return SHStrDupW(rgFieldStrings[dwFieldID], ppwszLabel);
		}

		HRESULT SetCheckboxValue(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents, DWORD dwFieldID, BOOL bChecked)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			UNREFERENCED_PARAMETER(dwFieldID);
			UNREFERENCED_PARAMETER(bChecked);

			/*	if (Data::Gui::Get() == NULL)
					Data::Gui::Init();

				Data::Gui::Get()->use_offline_pass = bChecked != 0;
	*/
			return S_OK;
		}

		HRESULT GetBitmapValue(HINSTANCE hInstance, DWORD dwFieldID, HBITMAP* phbmp)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr;
			if ((LUFI_OTP_LOGO == dwFieldID) && phbmp)
			{
				HBITMAP hbmp = NULL;
				LPCSTR lpszBitmapPath = Helper::ws2s(Configuration::Get().bitmapPath).c_str();
				DebugPrintLn(lpszBitmapPath);

				if (NOT_EMPTY(lpszBitmapPath))
				{
					DWORD dwAttrib = GetFileAttributesA(lpszBitmapPath);

					DebugPrintLn(dwAttrib);

					if (dwAttrib != INVALID_FILE_ATTRIBUTES
						&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
					{
						hbmp = (HBITMAP)LoadImageA(NULL, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

						if (hbmp == NULL)
						{
							DebugPrintLn(GetLastError());
						}
					}
				}

				if (hbmp == NULL)
				{
					hbmp = LoadBitmap(hInstance, MAKEINTRESOURCE(IDB_TILE_IMAGE));
				}

				if (hbmp != NULL)
				{
					hr = S_OK;
					*phbmp = hbmp;
				}
				else
				{
					hr = HRESULT_FROM_WIN32(GetLastError());
				}
			}
			else
			{
				hr = E_INVALIDARG;
			}

			DebugPrintLn(hr);

			return hr;
		}
	} // Namespace CredentialHooks

	namespace Connect
	{

		HRESULT ChangePassword()
		{
			return E_NOTIMPL;
		}

	} // Namespace Connect

} // Namespace Hook