#include "hooks.h"
#include <Lmcons.h>

namespace Hook
{

	namespace Serialization
	{

		DATA*& Get()
		{
			static struct DATA *data = NULL;

			return data;
		}

		void Default()
		{
			struct DATA*& data = Get();

			if (data == NULL)
				return;

			data->pcpcs = NULL;
			data->pcpgsr = NULL;
			data->status_icon = NULL;
			data->status_text = NULL;
			data->pCredProvCredentialEvents = NULL;
			data->pCredProvCredential = NULL;
		}

		void Init()
		{
			struct DATA*& data = Get();

			data = (struct DATA*) malloc(sizeof(struct DATA));

			Default();
		}

		void Deinit()
		{
			struct DATA*& data = Get();

			Default();

			free(data);
			data = NULL;
		}

		HRESULT Initialization(
			/*
			CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			PWSTR*& ppwszOptionalStatusText,
			CREDENTIAL_PROVIDER_STATUS_ICON*& pcpsiOptionalStatusIcon,
			ICredentialProviderCredentialEvents*& pCredProvCredentialEvents,
			ICredentialProviderCredential* pCredProvCredential
			*/)
		{
			DebugPrintLn(__FUNCTION__);

			if (Get() == NULL)
				Init();

			if (Get() == NULL)
				return HOOK_CRITICAL_FAILURE;

			Default();

			/*
			Hook::Serialization::Init(
				pcpgsr,
				pcpcs,
				ppwszOptionalStatusText,
				pcpsiOptionalStatusIcon,
				pCredProvCredentialEvents,
				pCredProvCredential);
			*/

			return S_OK;
		}

		HRESULT EndpointInitialization()
		{
			DebugPrintLn(__FUNCTION__);

			if (Endpoint::Get() == NULL)
				Endpoint::Init();

			if (Endpoint::Get() == NULL)
				return HOOK_CRITICAL_FAILURE;

			return S_OK;
		}

		HRESULT DataInitialization()
		{
			DebugPrintLn(__FUNCTION__);

			if (Data::General::Get()->bypassDataInitialization == true)
			{
				DebugPrintLn("Skipping...");

				Data::General::Get()->bypassDataInitialization = false;
				return S_FALSE;
			}

			if (Data::Gui::Get() == NULL)
				Data::Gui::Init();

			if (Data::Gui::Get() == NULL || Data::Provider::Get() == NULL)
				return HOOK_CRITICAL_FAILURE;

			// copy GUI fields to internal datastructures (we don't want to touch the GUI values)
			switch (Data::Provider::Get()->usage_scenario)
			{
			case CPUS_LOGON:
			case CPUS_UNLOCK_WORKSTATION:
				if (NOT_EMPTY(Data::Credential::Get()->user_name))
				{
					DebugPrintLn("Loading username from external credential");

					wcscpy_s(Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t), Data::Credential::Get()->user_name);

					if (NOT_EMPTY(Data::Credential::Get()->domain_name))
					{
						DebugPrintLn("Loading domainname from external credential");
						wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
					}
				}
				else
				{
					DebugPrintLn("Loading username/domainname from GUI");

					Helper::SeparateUserAndDomainName(Serialization::Get()->field_strings[LUFI_OTP_USERNAME],
						Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t),
						Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t)
					);

					if (EMPTY(Data::Gui::Get()->domain_name) && NOT_EMPTY(Data::Credential::Get()->domain_name))
					{
						DebugPrintLn("Loading domainname from external credential, because not provided in GUI");
						// user's choice has always precedence
						wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
					}
				}

				if (NOT_EMPTY(Data::Credential::Get()->password))
				{
					DebugPrintLn("Loading password from external credential");
					wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Data::Credential::Get()->password);
				}
				else
				{
					DebugPrintLn("Loading password from GUI");
					wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_LDAP_PASS]);
				}

				DebugPrintLn("Loading OTP from GUI");
				wcscpy_s(Data::Gui::Get()->otp_pass, sizeof(Data::Gui::Get()->otp_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_PASS]);

				break;
			case CPUS_CREDUI:
				/*
				if (NOT_EMPTY(Data::Credential::Get()->user_name))
				{
					DebugPrintLn("Loading username from external credential");

					wcscpy_s(Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t), Data::Credential::Get()->user_name);

					if (NOT_EMPTY(Data::Credential::Get()->domain_name))
					{
						DebugPrintLn("Loading domainname from external credential");
						wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
					}
				}
				else
				{
				*/
				DebugPrintLn("Loading username/domainname from GUI");

				Helper::SeparateUserAndDomainName(Serialization::Get()->field_strings[CFI_OTP_USERNAME],
					Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t),
					Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t)
				);

				if (EMPTY(Data::Gui::Get()->domain_name) && NOT_EMPTY(Data::Credential::Get()->domain_name))
				{
					DebugPrintLn("Loading domainname from external credential, because not provided in GUI");
					// user's choice has always precedence
					wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name); 
				}
				//}

				if (NOT_EMPTY(Data::Credential::Get()->password))
				{
					DebugPrintLn("Loading password from external credential");
					wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Data::Credential::Get()->password);
				}
				else
				{
					if (EMPTY(Data::Gui::Get()->ldap_pass)) {
						DebugPrintLn("Loading password from GUI");
						wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CFI_OTP_LDAP_PASS]);
					}
				}

				DebugPrintLn("Loading OTP from GUI");
				wcscpy_s(Data::Gui::Get()->otp_pass, sizeof(Data::Gui::Get()->otp_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CFI_OTP_PASS]);

				break;
			case CPUS_CHANGE_PASSWORD: {
				/////////////////////// UNSUPPORTED ///////////////////////////////////////
				wchar_t username[UNLEN + 1];
				DWORD username_len = UNLEN + 1;
				GetUserName(username, &username_len);
				DebugPrintLn("CHANGEPW USERNAME:");
				DebugPrintLn(username);

				wcscpy_s(username, sizeof(username) / sizeof(wchar_t), Data::Credential::Get()->user_name);


				if (!Data::Credential::Get()->domain_name) {
					wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
				}

				wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_OLD]);
				wcscpy_s(Data::Gui::Get()->ldap_pass_new_1, sizeof(Data::Gui::Get()->ldap_pass_new_1) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_NEW_1]);
				wcscpy_s(Data::Gui::Get()->ldap_pass_new_2, sizeof(Data::Gui::Get()->ldap_pass_new_2) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_NEW_2]);
				/////////////////////////////////////////////////////////////////////////////
				break; }
			default:
				return E_INVALIDARG;
			}

			return S_OK;
		}

		HRESULT EndpointLoadDebugData()
		{
			DebugPrintLn(__FUNCTION__);

#ifndef _DEBUG
			return S_FALSE;
#endif

			////
			return S_FALSE;
			////

			OutputDebugStringA("DEBUG: Loading (failing) demo user data John:123456 ..."); OutputDebugStringA("\n");

			wcscpy_s(Endpoint::Get()->username, sizeof(Endpoint::Get()->username) / sizeof(wchar_t), L"John");
			wcscpy_s(Endpoint::Get()->otpPass, sizeof(Endpoint::Get()->otpPass) / sizeof(wchar_t), L"123456"); // will fail
			wcscpy_s(Endpoint::Get()->ldapPass, sizeof(Endpoint::Get()->ldapPass) / sizeof(wchar_t), L"test"); // will fail

			OutputDebugStringA("DEBUG: ... END"); OutputDebugStringA("\n");

			return S_OK;
		}

		HRESULT EndpointLoadData()
		{
			DebugPrintLn(__FUNCTION__);
			if (!Data::General::Get()->bypassEndpoint) {
				if (NOT_EMPTY(Data::Gui::Get()->user_name))
				{
					DebugPrintLn("Copy username to epPack");
					wcscpy_s(Endpoint::Get()->username, sizeof(Endpoint::Get()->username) / sizeof(wchar_t), Data::Gui::Get()->user_name);
					DebugPrintLn(Endpoint::Get()->username);
				}
				else {
					DebugPrintLn("Data::Gui::Get()->username seems empty!");
				}


				if (NOT_EMPTY(Data::Gui::Get()->ldap_pass))
				{
					DebugPrintLn("Copy ldapPass to epPack");
					wcscpy_s(Endpoint::Get()->ldapPass, sizeof(Endpoint::Get()->ldapPass) / sizeof(wchar_t), Data::Gui::Get()->ldap_pass);
					DebugPrintLn(Endpoint::Get()->ldapPass);
				}
				else {
					DebugPrintLn("Data::Gui::Get()->ldap_pass seems empty!");
				}

				if (NOT_EMPTY(Data::Gui::Get()->otp_pass))
				{
					DebugPrintLn("Copy otpPass to epPack");
					wcscpy_s(Endpoint::Get()->otpPass, sizeof(Endpoint::Get()->otpPass) / sizeof(wchar_t), Data::Gui::Get()->otp_pass);
					DebugPrintLn(Endpoint::Get()->otpPass);
				}
				else {
					DebugPrintLn("Data::Gui::Get()->otp_pass seems empty!");
				}
			}
			return S_OK;
		}

		HRESULT EndpointCallCancelled()
		{
			DebugPrintLn(__FUNCTION__);

			Endpoint::Get()->protectMe = false;

			SHStrDupW(L"Logon cancelled", Hook::Serialization::Get()->status_text);

			*Hook::Serialization::Get()->status_icon = CPSI_ERROR;
			*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

			return S_OK;
		}

		HRESULT EndpointCallSuccessfull()
		{
			DebugPrintLn(__FUNCTION__);

			Endpoint::Get()->protectMe = false;

			return S_OK;
		}

		HRESULT EndpointCallContinue()
		{
			DebugPrintLn(__FUNCTION__);

			Endpoint::Get()->protectMe = true;
			Data::General::Get()->bypassDataDeinitialization = true;

			INIT_ZERO_WCHAR(endpoint_instruction_msg, ENDPOINT_INSTRUCTION_MSG_SIZE);
			INIT_ZERO_WCHAR(instruction_message, ENDPOINT_INSTRUCTION_MSG_SIZE + 100);

			bool *big;

			Endpoint::GetLastInstructionDescription(endpoint_instruction_msg, big);

			if (endpoint_instruction_msg[0] == NULL)
				return S_FALSE;

			if (big)
			{
				swprintf_s(instruction_message, sizeof(instruction_message) / sizeof(wchar_t), L"The endpoint requires further interaction on your side. Code: %X\n\n%s",
							Endpoint::GetLastErrorCode(), endpoint_instruction_msg);
				SHStrDupW(instruction_message, Hook::Serialization::Get()->status_text);

				*Hook::Serialization::Get()->status_icon = CPSI_SUCCESS;
			}
			else
			{
				///// Concrete Endpoint
				//Data::General::Get()->startEndpointObserver = true;
				Data::General::Get()->clearFields = false;
				/////
				General::Fields::SetScenario(Hook::Serialization::Get()->pCredProvCredential, Hook::Serialization::Get()->pCredProvCredentialEvents,
											 General::Fields::SCENARIO_SECOND_STEP, NULL, endpoint_instruction_msg);
			}

			return S_OK;
		}

		HRESULT EndpointCallFailed()
		{
			DebugPrintLn(__FUNCTION__);

			Endpoint::Get()->protectMe = false;

			INIT_ZERO_WCHAR(endpoint_error_msg, ENDPOINT_ERROR_MSG_SIZE);
			INIT_ZERO_WCHAR(error_message, ENDPOINT_ERROR_MSG_SIZE + 100);

			Endpoint::GetLastErrorDescription(endpoint_error_msg);

			swprintf_s(error_message, sizeof(error_message) / sizeof(wchar_t), L"An error occured. Error Code: %X\n\n%s", Endpoint::GetLastErrorCode(), endpoint_error_msg);
			SHStrDupW(error_message, Hook::Serialization::Get()->status_text);

			*Hook::Serialization::Get()->status_icon = CPSI_ERROR;

			return S_OK;
		}

		HRESULT EndpointDeinitialization()
		{
			DebugPrintLn(__FUNCTION__);

			Endpoint::Deinit();

			return S_OK;
		}

		HRESULT DataDeinitialization()
		{
			DebugPrintLn(__FUNCTION__);

			if (Data::General::Get()->bypassDataDeinitialization == true)
			{
				DebugPrintLn("Skipping...");

				Data::General::Get()->bypassDataDeinitialization = false;
				return S_FALSE;
			}

			Data::Gui::Deinit();

			// Leave provider data intact

			return S_OK;
		}

		/////////////

		HRESULT ChangePasswordSuccessfull()
		{
			DebugPrintLn(__FUNCTION__);
			
			if (Data::Credential::Get()->passwordMustChange) {
				Data::Credential::Get()->passwordChanged = true;
				Data::General::Get()->clearFields = false;
			//	Data::General::Get()->bypassDataDeinitialization = false;
				Data::General::Get()->bypassDataDeinitialization = true;
				Data::Credential::Get()->passwordMustChange = false;
			}

			//SHStrDupW(L"Your password was successfully changed.", Hook::Serialization::Get()->status_text);

			*Hook::Serialization::Get()->pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
			*Hook::Serialization::Get()->status_icon = CPSI_SUCCESS;

			return S_OK;
		}

		HRESULT ChangePasswordFailed()
		{
			DebugPrintLn(__FUNCTION__);
			SHStrDupW(L"Your password could not be changed. Make sure you correctly typed your new password twice.", Hook::Serialization::Get()->status_text);

			*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			*Hook::Serialization::Get()->status_icon = CPSI_ERROR;

			return S_OK;
		}

		/////////////

		HRESULT KerberosCallSuccessfull() { return S_OK; }

		HRESULT KerberosCallFailed() { return S_OK; }

		/////////////

		HRESULT BeforeReturn()
		{
			DebugPrintLn(__FUNCTION__);

			Data::Credential::Get()->endpointStatus = E_NOT_SET; // Reset for second run

			Hook::Serialization::Deinit();

			return S_OK;
		}

	} // Namespace Serialization

	namespace CredentialHooks
	{
		// switch passwordChanged and turn on AutoLogon
		HRESULT CheckPasswordChanging(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, BOOL *&pbAutoLogon)
		{
			DebugPrintLn(__FUNCTION__);
			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			if (Data::Credential::Get()->passwordMustChange)
			{
				DebugPrintLn("CheckPasswordChanging TRUE");

				//General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_CHANGE_PASSWORD);
				//Data::Credential::Get()->passwordMustChange = false;
				return E_ABORT;
			}

			if (Data::Credential::Get()->passwordChanged) {
				//Data::Credential::Get()->passwordChanged = false;
				Data::General::Get()->bypassDataInitialization = true; // we dont want to initialize the kiul with the old password
				*pbAutoLogon = TRUE;
			}

			return S_OK;
		}

		HRESULT CheckEndpointObserver(BOOL *&pbAutoLogon)
		{
			DebugPrintLn(__FUNCTION__);

			if (EndpointObserver::Thread::GetStatus() == EndpointObserver::Thread::STATUS::FINISHED)
			{
				DebugPrintLn("Observer FINISHED");

				if (EndpointObserver::Result()->returnValue == EPT_SUCCESS)
				{
					DebugPrintLn("EPT_SUCCESS");

					EndpointObserver::Result()->returnValue = EPT_UNKNOWN;
					Data::General::Get()->bypassEndpoint = true;
					Data::General::Get()->bypassDataInitialization = true;

					*pbAutoLogon = true;
				}
				else
				{
					DebugPrintLn("EPT_FAILURE or EPT_UNKNOWN");

					Endpoint::Get()->protectMe = false;
					Hook::Serialization::EndpointDeinitialization();

					return E_FAIL;
				}

				EndpointObserver::Thread::Destroy();
			}

			return S_OK;
		}

		HRESULT ResetScenario(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents)
		{
			DebugPrintLn(__FUNCTION__);

			if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION)
			{
				if (Configuration::Get()->two_step_hide_otp) {
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_TWO_STEP, NULL, WORKSTATION_LOCKED);
				}
				else {
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_BASE, NULL, WORKSTATION_LOCKED);
				}

			}
			else if (Data::Provider::Get()->usage_scenario == CPUS_LOGON)
			{
				if (Configuration::Get()->two_step_hide_otp) {
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_LOGON_TWO_STEP);
				}
				else {
					General::Fields::SetScenario(pSelf, pCredProvCredentialEvents, General::Fields::SCENARIO_LOGON_BASE);
				}
			}

			return S_OK;
		}

		HRESULT GetSubmitButtonValue(DWORD dwFieldID, DWORD* &pdwAdjacentTo)
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

		HRESULT GetComboBoxValueCount(DWORD dwFieldID, DWORD* &pcItems, DWORD* &pdwSelectedItem)
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

		HRESULT GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* &ppwszItem)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(dwFieldID);
			UNREFERENCED_PARAMETER(dwItem);
			UNREFERENCED_PARAMETER(ppwszItem);

			HRESULT hr;

			hr = E_INVALIDARG; //SHStrDupW(s_rgLogonUnlockComboBoxModeStrings[dwItem], ppwszItem);

			return hr;
		}

		HRESULT SetComboBoxSelectedValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents,
										 DWORD dwFieldID, DWORD dwSelectedItem, DWORD &dwSelectedItemBuffer)
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

		HRESULT GetCheckboxValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, wchar_t **rgFieldStrings,
								 DWORD dwFieldID, BOOL *&pbChecked, PWSTR *&ppwszLabel)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);

			if (Data::Gui::Get() == NULL)
				Data::Gui::Init();

			*pbChecked = Data::Gui::Get()->use_offline_pass;
			return SHStrDupW(rgFieldStrings[dwFieldID], ppwszLabel);
		}

		HRESULT SetCheckboxValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, DWORD dwFieldID, BOOL bChecked)
		{
			DebugPrintLn(__FUNCTION__);

			UNREFERENCED_PARAMETER(pSelf);
			UNREFERENCED_PARAMETER(pCredProvCredentialEvents);
			UNREFERENCED_PARAMETER(dwFieldID);

			if (Data::Gui::Get() == NULL)
				Data::Gui::Init();

			Data::Gui::Get()->use_offline_pass = bChecked != 0;

			return S_OK;
		}

		HRESULT GetBitmapValue(HINSTANCE hInstance, DWORD dwFieldID, HBITMAP* phbmp)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr;
			if ((LUFI_OTP_LOGO == dwFieldID) && phbmp)
			{
				HBITMAP hbmp = NULL;

				DebugPrintLn(Configuration::Get()->v1_bitmap_path);

				if (NOT_EMPTY(Configuration::Get()->v1_bitmap_path))
				{
					DWORD dwAttrib = GetFileAttributesA(Configuration::Get()->v1_bitmap_path);

					DebugPrintLn(dwAttrib);

					if (dwAttrib != INVALID_FILE_ATTRIBUTES
						&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
					{
						hbmp = (HBITMAP)LoadImageA(NULL, Configuration::Get()->v1_bitmap_path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

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