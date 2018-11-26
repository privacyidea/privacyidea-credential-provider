/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
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
** * * * * * * * * * * * * * * * * * * */

#ifndef _CPROVIDER_H
#define _CPROVIDER_H

#include <windows.h>
#include <strsafe.h>
#include <Wtsapi32.h>						
#include <Lm.h>
#include <credentialprovider.h>

#include <helpers.h>

#include "CCredential.h"

#include "dependencies.h"

#define MAX_CREDENTIALS 3
#define MAX_DWORD   0xffffffff        // maximum DWORD

enum SERIALIZATION_AVAILABLE_FOR
{
	SAF_USERNAME,
	SAF_PASSWORD,
	SAF_DOMAIN
};


BOOL IsCurrentSessionRemoteable();

class CProvider : public ICredentialProvider
{
public:
	// IUnknown
	IFACEMETHODIMP_(ULONG) AddRef()
	{
		return ++_cRef;
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		LONG cRef = --_cRef;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	#pragma warning( disable : 4838 )
	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
	{
		static const QITAB qit[] =
		{
			QITABENT(CProvider, ICredentialProvider), // IID_ICredentialProvider
			{ 0 },
		};
		return QISearch(this, qit, riid, ppv);
	}

public:
	//void Redraw();

	IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags);
	IFACEMETHODIMP SetSerialization(__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

	IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext);
	IFACEMETHODIMP UnAdvise();

	IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
	IFACEMETHODIMP GetFieldDescriptorAt(__in DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

	IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
		__out_range(<, *pdwCount) DWORD* pdwDefault,
		__out BOOL* pbAutoLogonWithDefault);
	IFACEMETHODIMP GetCredentialAt(__in DWORD dwIndex,
		__deref_out ICredentialProviderCredential** ppcpc);

	friend HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);
	
protected:
	CProvider();
	__override ~CProvider();

private:

	HRESULT _EnumerateOneCredential(__in DWORD dwCredientialIndex,
		__in PCWSTR pwzUsername);
	//HRESULT _EnumerateSetSerialization();

	// Create/free enumerated credentials.
	//HRESULT _EnumerateCredentials(__in_opt PWSTR user_name, __in_opt PWSTR domain_name);

	void _ReleaseEnumeratedCredentials();
	void _CleanupSetSerialization();

	void _GetSerializedCredentials(PWSTR *username, PWSTR *password, PWSTR *domain);
	bool _SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor);


private:
	LONG									_cRef;
	//CCredential								*_rgpCredentials[MAX_CREDENTIALS];  // Pointers to the credentials which will be enumerated by 

	// this Provider.
	//DWORD                                   _dwNumCreds;
	KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
	DWORD                                   _dwSetSerializationCred; //index into rgpCredentials for the SetSerializationCred
	bool                                    _bAutoSubmitSetSerializationCred;
	//CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;

	//ICredentialProviderEvents*				_pcpe;
	//UINT_PTR								_upAdviseContext;

	CCredential*							_pccCredential;
};

#endif
