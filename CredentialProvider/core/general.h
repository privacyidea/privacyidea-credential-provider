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

#ifndef _GENERAL_H
#define _GENERAL_H
#pragma once

#include <helpers.h>
#include <wincred.h>

#include "common.h"
#include "data.h"

#include "general_field_states.h"

namespace General
{
#define MAX_SIZE_DOMAIN 64

	namespace Logon
	{
		HRESULT KerberosLogon(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			);

		HRESULT KerberosChangePassword(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
			__in PWSTR username,
			__in PWSTR password_old,
			__in PWSTR password_new,
			__in PWSTR domain
			);

		HRESULT CredPackAuthentication(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			);
	}

	namespace Fields
	{
		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			);

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario
			);

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			);

#define CLEAR_FIELDS_CRYPT 0
#define CLEAR_FIELDS_EDIT_AND_CRYPT 1
#define CLEAR_FIELDS_ALL 2
#define CLEAR_FIELDS_ALL_DESTROY 3

		HRESULT Clear(
			wchar_t* (&field_strings)[MAX_NUM_FIELDS],
			CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[MAX_NUM_FIELDS],
			ICredentialProviderCredential* pcpc,
			ICredentialProviderCredentialEvents* pcpce,
			char clear);

		HRESULT SetFieldStatePairBatch(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in const FIELD_STATE_PAIR* pFSP
			);

		unsigned int GetCurrentNumFields();

		HRESULT InitializeField(LPWSTR *rgFieldStrings, const FIELD_INITIALIZOR initializor, DWORD field_index);
	}
}

#endif
