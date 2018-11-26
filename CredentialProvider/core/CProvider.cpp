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

#include <credentialprovider.h>
#include "CProvider.h"
#include "version.h"

// CProvider ////////////////////////////////////////////////////////

CProvider::CProvider() :
	_cRef(1),
	_pkiulSetSerialization(NULL),
	_pccCredential(NULL),
	//_dwNumCreds(0),
	_bAutoSubmitSetSerializationCred(false),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT)
{
	DllAddRef();

	// Initialize config
	Configuration::Init();
	Configuration::Read();

	Data::Provider::Init();
}

CProvider::~CProvider()
{
	if (_pccCredential != NULL)
	{
		_pccCredential->Release();
	}

	Data::Provider::Deinit();

	DllRelease();
}

void CProvider::_CleanupSetSerialization()
{
	DebugPrintLn(__FUNCTION__);

	if (_pkiulSetSerialization)
	{
		KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
		SecureZeroMemory(_pkiulSetSerialization,
			sizeof(*_pkiulSetSerialization) +
			pkil->LogonDomainName.MaximumLength +
			pkil->UserName.MaximumLength +
			pkil->Password.MaximumLength);
		HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
	}
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.  
//
// This sample only handles the logon and unlock scenarios as those are the most common.
HRESULT CProvider::SetUsageScenario(
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in DWORD dwFlags
)
{
#ifdef _DEBUG
	DebugPrintLn(__FUNCTION__);
	DebugPrintLn(cpus);
	Configuration::PrintConfig();
#endif
	HRESULT hr = E_INVALIDARG;

	Data::Provider::Get()->credPackFlags = dwFlags;
	Data::Provider::Get()->usage_scenario = cpus;

	// Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
	// that we're not designed for that scenario.
	switch (Data::Provider::Get()->usage_scenario)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
		if (IsCurrentSessionRemoteable()) {
			// if current session is remote, we need to get the OTP before the auth to pi, so we turn 2step on anyway
			Configuration::Get()->two_step_hide_otp = 1;
			Configuration::Get()->two_step_send_empty_password = 0;
			Configuration::Get()->two_step_send_password = 0;
			DebugPrintLn("remote session detected - turning on 2step on the server.");
		}

		hr = S_OK;
		break;
	case CPUS_CREDUI:
		// turn off two step in case of CredUI
		Configuration::Get()->two_step_hide_otp = 0;
		Configuration::Get()->two_step_send_empty_password = 0;
		Configuration::Get()->two_step_send_password = 0;
		hr = S_OK;
		break;

	case CPUS_CHANGE_PASSWORD:
	case CPUS_PLAP:
	case CPUS_INVALID:
		hr = E_NOTIMPL;
		break;

	default:
		hr = E_INVALIDARG;
	}

	DebugPrintLn("CSample_CreateInstance Result:");
	DebugPrintLn(hr);

	return hr;
}

#define TERMINAL_SERVER_KEY _T("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    _T("GlassSessionId")

BOOL IsCurrentSessionRemoteable()
{
	BOOL fIsRemoteable = FALSE;
	DebugPrintLn("check for remote session...");
	if (GetSystemMetrics(SM_REMOTESESSION))
	{
		fIsRemoteable = TRUE;
	}
	else
	{
		HKEY hRegKey = NULL;
		LONG lResult;

		lResult = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			TERMINAL_SERVER_KEY,
			0, // ulOptions
			KEY_READ,
			&hRegKey
		);

		if (lResult == ERROR_SUCCESS)
		{
			DWORD dwGlassSessionId;
			DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
			DWORD dwType;

			lResult = RegQueryValueEx(
				hRegKey,
				GLASS_SESSION_ID,
				NULL, // lpReserved
				&dwType,
				(BYTE*)&dwGlassSessionId,
				&cbGlassSessionId
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwCurrentSessionId;

				if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
				{
					fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
				}
			}
		}

		if (hRegKey)
		{
			RegCloseKey(hRegKey);
		}
	}
	if (fIsRemoteable)
	{
		DebugPrintLn("... returning - is remote session!");
	}
	else
	{
		DebugPrintLn("... returning - is not remote session!");
	}
	return fIsRemoteable;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt. It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a credential.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// Since this sample doesn't support CPUS_CREDUI, we have not implemented the credui specific
// pieces of this function.  For information on that, please see the credUI sample.
HRESULT CProvider::SetSerialization(
	__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
)
{
	DebugPrintLn(__FUNCTION__);
	HRESULT result = E_NOTIMPL;
	ULONG authPackage = NULL;
	result = RetrieveNegotiateAuthPackage(&authPackage);

	if (!SUCCEEDED(result))
	{
		DebugPrintLn("Failed to retrieve authPackage");
		return result;
	}

	if (Data::Provider::Get()->usage_scenario == CPUS_CREDUI)
	{
		DebugPrintLn("CPUS_CREDUI");

		if (((Data::Provider::Get()->credPackFlags & CREDUIWIN_IN_CRED_ONLY) || (Data::Provider::Get()->credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY))
				&& authPackage != pcpcs->ulAuthenticationPackage)
		{
			DebugPrintLn("authPackage invalid");
			return E_INVALIDARG;
		}

		if (Data::Provider::Get()->credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY)
		{
			DebugPrintLn("CPUS_CREDUI but not CREDUIWIN_AUTHPACKAGE_ONLY");
			result = S_FALSE;
		}
	}

	if (authPackage == pcpcs->ulAuthenticationPackage && pcpcs->cbSerialization > 0 && pcpcs->rgbSerialization)
	{
		KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
		if (pkil->Logon.MessageType == KerbInteractiveLogon)
		{
			if (pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
			{
				BYTE * nativeSerialization = NULL;
				DWORD nativeSerializationSize = 0;

				if (Data::Provider::Get()->credPackFlags == CPUS_CREDUI && (Data::Provider::Get()->credPackFlags & CREDUIWIN_PACK_32_WOW))
				{
					if (!SUCCEEDED(KerbInteractiveUnlockLogonRepackNative(pcpcs->rgbSerialization, pcpcs->cbSerialization,
						&nativeSerialization, &nativeSerializationSize)))
					{
						return result;
					}
				}
				else
				{
					nativeSerialization = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pcpcs->cbSerialization);
					nativeSerializationSize = pcpcs->cbSerialization;

					if (!nativeSerialization)
						return E_OUTOFMEMORY;

					CopyMemory(nativeSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
				}

				KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON *)nativeSerialization, nativeSerializationSize);

				if (_pkiulSetSerialization)
					LocalFree(_pkiulSetSerialization);

				_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON *)nativeSerialization;

				result = S_OK;
			}
		}
	}
	DebugPrintLn(result);

	return result;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated
HRESULT CProvider::Advise(
	__in ICredentialProviderEvents* pcpe,
	__in UINT_PTR upAdviseContext
)
{
	DebugPrintLn(__FUNCTION__);

	if (Data::Provider::Get()->_pcpe != NULL)
	{
		Data::Provider::Get()->_pcpe->Release();
	}

	Data::Provider::Get()->_pcpe = pcpe;
	Data::Provider::Get()->_pcpe->AddRef();

	Data::Provider::Get()->_upAdviseContext = upAdviseContext;

	return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CProvider::UnAdvise()
{
	DebugPrintLn(__FUNCTION__);

	if (Data::Provider::Get()->_pcpe != NULL)
	{
		Data::Provider::Get()->_pcpe->Release();
	}

	Data::Provider::Get()->_pcpe = NULL;
	Data::Provider::Get()->_upAdviseContext = NULL;

	return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired 
// using the field descriptors.
HRESULT CProvider::GetFieldDescriptorCount(
	__out DWORD* pdwCount
)
{
	DebugPrintLn(__FUNCTION__);

	*pdwCount = General::Fields::GetCurrentNumFields();

	return S_OK;
}

// Gets the field descriptor for a particular field
HRESULT CProvider::GetFieldDescriptorAt(
	__in DWORD dwIndex,
	__deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr;

	// Verify dwIndex is a valid field.
	if ((dwIndex < General::Fields::GetCurrentNumFields()) && ppcpfd)
	{
		hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptorsFor[Data::Provider::Get()->usage_scenario][dwIndex],
										ppcpfd, Configuration::Get()->otp_text);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
//
// The default tile is the tile which will be shown in the zoomed view by default. If 
// more than one provider specifies a default tile the behavior is the last used cred
// prov gets to specify the default tile to be displayed
//
// If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call GetSerialization
// on the credential you've specified as the default and will submit that credential
// for authentication without showing any further UI.
HRESULT CProvider::GetCredentialCount(
	__out DWORD* pdwCount,
	__out_range(< , *pdwCount) DWORD* pdwDefault,
	__out BOOL* pbAutoLogonWithDefault
)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	*pdwCount = 1; //_dwNumCreds;
	*pdwDefault = 0; // this means we want to be the default

	if (Configuration::Get()->no_default) {
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
	}
	*pbAutoLogonWithDefault = FALSE;

	// if serialized creds are available, try using them to logon
	if (_SerializationAvailable(SAF_USERNAME) && _SerializationAvailable(SAF_PASSWORD))
	{
		*pdwDefault = 0;
		*pbAutoLogonWithDefault = TRUE;
	}

	DebugPrintLn(hr);

	return hr;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CProvider::GetCredentialAt(
	__in DWORD dwIndex,
	__deref_out ICredentialProviderCredential** ppcpc
)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr = E_FAIL;

	if (!_pccCredential)
	{
		DebugPrintLn("Checking for serialized credentials");

		PWSTR serializedUser, serializedPass, serializedDomain;
		_GetSerializedCredentials(&serializedUser, &serializedPass, &serializedDomain);

		DebugPrintLn("Checking for missing credentials");

		if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION && serializedUser == NULL)
		{
			if (serializedUser == NULL)
			{
				DebugPrintLn("Looking-up missing user name from session");

				DWORD dwLen;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSUserName,
					&serializedUser,
					&dwLen))
				{
					serializedUser = NULL;
				}
			}

			if (serializedDomain == NULL)
			{
				DebugPrintLn("Looking-up missing domain name from session");

				DWORD dwLen;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSDomainName,
					&serializedDomain,
					&dwLen))
				{
					serializedDomain = NULL;
				}
			}
		}
		else if (Data::Provider::Get()->usage_scenario == CPUS_LOGON || Data::Provider::Get()->usage_scenario == CPUS_CREDUI)
		{
			if (serializedDomain == NULL)
			{
				DebugPrintLn("Looking-up missing domain name from computer");

				NETSETUP_JOIN_STATUS join_status;

				if (!NetGetJoinInformation(
					NULL,
					&serializedDomain,
					&join_status) == NERR_Success || join_status == NetSetupUnjoined || join_status == NetSetupUnknownStatus)
				{
					serializedDomain = NULL;
				}
				DebugPrintLn("Found domain:");
				DebugPrintLn(serializedDomain);
			}
		}

		DebugPrintLn("Initializing CCredential");

		_pccCredential = new CCredential();
		hr = _pccCredential->Initialize(s_rgCredProvFieldDescriptorsFor[Data::Provider::Get()->usage_scenario], 
										General::Fields::GetFieldStatePairFor(Data::Provider::Get()->usage_scenario), serializedUser, 
										serializedDomain, serializedPass);
	}
	else
	{
		hr = S_OK;
	}

	DebugPrintLn("Checking for successful initialization");

	if (FAILED(hr))
	{
		DebugPrintLn("Initialization failed");
		return hr;
	}

	DebugPrintLn("Checking for successful instantiation");

	if (!_pccCredential)
	{
		DebugPrintLn("Instantiation failed");
		return E_OUTOFMEMORY;
	}

	DebugPrintLn("Returning interface to credential");

	// Validate parameters.
	//if((dwIndex < _dwNumCreds) && ppcpc)
	if ((dwIndex == 0) && ppcpc)
	{
		if (Data::Provider::Get()->usage_scenario == CPUS_CREDUI)
		{
			DebugPrintLn("CredUI: returning an IID_ICredentialProviderCredential");
			hr = _pccCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(ppcpc));
		}
		else
		{
			DebugPrintLn("Non-CredUI: returning an IID_IConnectableCredentialProviderCredential");
			hr = _pccCredential->QueryInterface(IID_IConnectableCredentialProviderCredential, reinterpret_cast<void **>(ppcpc));
			//hr = _pccCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(ppcpc));
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	DebugPrintLn(__FUNCTION__);
	HRESULT hr;

	CProvider* pProvider = new CProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}
	DebugPrintLn("CSample_CreateInstance Result:");
	DebugPrintLn(hr);

	return hr;
}

void CProvider::_GetSerializedCredentials(PWSTR *username, PWSTR *password, PWSTR *domain)
{
	DebugPrintLn(__FUNCTION__);

	if (username)
	{
		if (_SerializationAvailable(SAF_USERNAME))
		{
			*username = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.UserName.Length + sizeof(wchar_t));
			CopyMemory(*username, _pkiulSetSerialization->Logon.UserName.Buffer, _pkiulSetSerialization->Logon.UserName.Length);
		}
		else
			*username = NULL;
	}

	if (password)
	{
		if (_SerializationAvailable(SAF_PASSWORD))
		{
			*password = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.Password.Length + sizeof(wchar_t));
			CopyMemory(*password, _pkiulSetSerialization->Logon.Password.Buffer, _pkiulSetSerialization->Logon.Password.Length);
		}
		else
			*password = NULL;
	}

	if (domain)
	{
		if (_SerializationAvailable(SAF_DOMAIN))
		{
			*domain = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.LogonDomainName.Length + sizeof(wchar_t));
			CopyMemory(*domain, _pkiulSetSerialization->Logon.LogonDomainName.Buffer, _pkiulSetSerialization->Logon.LogonDomainName.Length);
		}
		else
			*domain = NULL;
	}
}

bool CProvider::_SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor)
{
	DebugPrintLn(__FUNCTION__);

	bool result = false;

	if (!_pkiulSetSerialization)
	{
		DebugPrintLn("No serialized creds set");
	}
	else {
		switch (checkFor)
		{
		case SAF_USERNAME:
			result = _pkiulSetSerialization->Logon.UserName.Length && _pkiulSetSerialization->Logon.UserName.Buffer;
			break;
		case SAF_PASSWORD:
			result = _pkiulSetSerialization->Logon.Password.Length && _pkiulSetSerialization->Logon.Password.Buffer;
			break;
		case SAF_DOMAIN:
			result = _pkiulSetSerialization->Logon.LogonDomainName.Length && _pkiulSetSerialization->Logon.LogonDomainName.Buffer;
			break;
		}
	}

	return result;
}
