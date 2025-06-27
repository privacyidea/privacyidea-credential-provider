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

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include "CCredentialProviderFilter.h"
#include "guid.h"
#include "Logger.h"
#include "Shared.h"
#include "Convert.h"
#include <unknwn.h>
#include <RegistryReader.h>

HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	RegistryReader rr(CONFIG_REGISTRY_PATH);
	Logger::Get().logDebug = rr.GetBool(L"debug_log");

	PIDebug(std::string(__FUNCTION__) + " - FILTER START");
	HRESULT hr;

	CCredentialProviderFilter* pProvider = new CCredentialProviderFilter();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT CCredentialProviderFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders,
	BOOL* rgbAllow, DWORD cProviders)
{
	UNREFERENCED_PARAMETER(dwFlags);
	PIDebug(std::string(__FUNCTION__) + " " + Shared::CPUStoString(cpus));

	RegistryReader rr(CONFIG_REGISTRY_PATH);
	_filterEnabled = rr.GetBool(L"enable_filter");

	if (!_filterEnabled)
	{
		PIDebug("Filter disabled by registry setting!");
		return S_OK;
	}

	switch (cpus)
	{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
			break;
		case CPUS_CHANGE_PASSWORD:
			return E_NOTIMPL;
		default:
			return E_INVALIDARG;
	}

	if (!Shared::IsRequiredForScenario(cpus, FILTER))
	{
		PIDebug("Filter is configured to be disabled for this scenario.");
		return S_OK;
	}

	std::vector<GUID> whitelistedGUIDs;
	auto whitelist = rr.GetMultiSZ(L"filter_whitelist");
	// If its CredUI, add the FIDO CP to the whitelist, so security keys can be selected
	if (cpus == CPUS_CREDUI)
	{
		whitelist.push_back(L"{F8A1793B-7873-4046-B2A7-1F318747F427}");
	}
	if (!whitelist.empty())
	{
		PIDebug("Entries for filter whitelist found:");
		PIDebug(Convert::JoinW(whitelist, L", "));
		HRESULT hr = S_OK;
		// Convert the wstrings to GUIDs
		for (auto& ws : whitelist)
		{
			CLSID clsid;
			hr = CLSIDFromString(ws.c_str(), &clsid);
			if (SUCCEEDED(hr))
			{
				whitelistedGUIDs.push_back(clsid);
				PIDebug(L"Added " + ws + L" to whitelisted GUIDs");
			}
			else
			{
				PIError(L"Failed to convert " + ws + L" to GUID. Check if the format is correct.");
			}
		}
	}

	for (DWORD i = 0; i < cProviders; i++)
	{
		rgbAllow[i] = FALSE;

		// Check if it is our own provider
		if (IsEqualGUID(rgclsidProviders[i], CLSID_COTP_LOGON))
		{
			rgbAllow[i] = TRUE;
		}

		// Check if it a whitelisted provider
		for (auto& guid : whitelistedGUIDs)
		{
			if (IsEqualGUID(rgclsidProviders[i], guid))
			{
				rgbAllow[i] = TRUE;
			}
		}
	}

	return S_OK;
}

CCredentialProviderFilter::CCredentialProviderFilter() :
	_cRef(1)
{
	PIDebug(__FUNCTION__);
	DllAddRef();
}

CCredentialProviderFilter::~CCredentialProviderFilter()
{
	PIDebug(__FUNCTION__);
	DllRelease();
}

HRESULT CCredentialProviderFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
	//UNREFERENCED_PARAMETER(pcpsIn);
	//UNREFERENCED_PARAMETER(pcpcsOut);
	PIDebug(__FUNCTION__);

	if (!pcpcsIn)
	{
		// no point continuing as there are no credentials
		return E_NOTIMPL;
	}

	// copy contents from pcpcsIn to pcpcsOut
	pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
	pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
	pcpcsOut->rgbSerialization = pcpcsIn->rgbSerialization;

	// set target CP to our CP
	pcpcsOut->clsidCredentialProvider = CLSID_COTP_LOGON;

	// copy the buffer contents if needed
	if (pcpcsOut->cbSerialization > 0 && (pcpcsOut->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcsIn->cbSerialization)) != NULL)
	{
		CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
		return S_OK;
	}
	else
	{
		return E_NOTIMPL;
	}
}