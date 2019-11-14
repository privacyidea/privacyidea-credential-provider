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

#ifndef _HOOKS_H
#define _HOOKS_H
#pragma once

#include <Shlwapi.h>

#include "common.h"

#include "general.h"
#include "endpoint.h"

namespace Hook
{
#define HOOK_CRITICAL_FAILURE		((HRESULT)0x8880A001)
#define HOOK_CHECK_CRITICAL(hook, trap) if (hook == HOOK_CRITICAL_FAILURE) { DebugPrintLn("Critical Hook Failure"); goto trap; }

	namespace Serialization
	{
		/*
		struct DATA
		{
			// Possibly read-write
			CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr;
			CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs;
			PWSTR* status_text;
			CREDENTIAL_PROVIDER_STATUS_ICON* status_icon;
			ICredentialProviderCredentialEvents* pCredProvCredentialEvents;

			// Read-only
			ICredentialProviderCredential* pCredProvCredential;
			wchar_t** field_strings;
			int num_field_strings;
		};

		DATA*& Get();
		void Init();
		void Deinit();
		void Default();
		*/
		HRESULT ReadFieldValues();

		HRESULT ReadUserField();
		HRESULT ReadPasswordField();
		HRESULT ReadOTPField();

		HRESULT EndpointCallCancelled();
		HRESULT EndpointCallSuccessfull();
		HRESULT PrepareSecondStep();
		HRESULT EndpointCallFailed();
		HRESULT DataDeinitialization();

		HRESULT ChangePasswordSuccessfull();
		HRESULT ChangePasswordFailed();

		HRESULT KerberosCallSuccessfull();
		HRESULT KerberosCallFailed();

		HRESULT BeforeReturn();
	}

	namespace CredentialHooks
	{
		HRESULT CheckPasswordChanging(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, BOOL *&pbAutoLogon);
		HRESULT CheckEndpointObserver(BOOL *&pbAutoLogon);
		HRESULT ResetScenario(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents);
		HRESULT GetSubmitButtonValue(DWORD dwFieldID, DWORD* &pdwAdjacentTo);
		HRESULT GetComboBoxValueCount(DWORD dwFieldID, DWORD* &pcItems, DWORD* &pdwSelectedItem);
		HRESULT GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* &ppwszItem);
		HRESULT SetComboBoxSelectedValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, DWORD dwFieldID, DWORD dwSelectedItem, DWORD &dwSelectedItemBuffer);
		HRESULT GetCheckboxValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, wchar_t **rgFieldStrings, DWORD dwFieldID, BOOL *&pbChecked, PWSTR *&ppwszLabel);
		HRESULT SetCheckboxValue(ICredentialProviderCredential *pSelf, ICredentialProviderCredentialEvents *pCredProvCredentialEvents, DWORD dwFieldID, BOOL bChecked);
		HRESULT GetBitmapValue(HINSTANCE hInstance, DWORD dwFieldID, HBITMAP* phbmp);
	}

	namespace Connect
	{
		HRESULT ChangePassword();
	}
}

#endif
