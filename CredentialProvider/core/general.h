#ifndef _GENERAL_H
#define _GENERAL_H
#pragma once

#include <helpers.h>
#include <wincred.h>

#include "common.h"
#include "data.h"
#include "config.h"

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
