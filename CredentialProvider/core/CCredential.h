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

#pragma once

#include "Dll.h"
#include "Utilities.h"
#include "Configuration.h"
#include "PrivacyIDEA.h"
#include "FIDO2Device.h"
#include <scenario.h>
#include <unknwn.h>
#include <helpers.h>
#include <string>
#include <map>
#include <optional>

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define ZERO(NAME) \
	SecureZeroMemory(NAME, sizeof(NAME))

class CCredential : public IConnectableCredentialProviderCredential
{
public:
	// IUnknown
	IFACEMETHODIMP_(ULONG) AddRef() noexcept override
	{
		return ++_cRef;
	}

	IFACEMETHODIMP_(ULONG) Release() noexcept override
	{
		LONG cRef = --_cRef;
		if (!cRef)
		{
			// The Credential is owned by the Provider object
		}
		return cRef;
	}

#pragma warning( disable : 4838 )
	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv) noexcept override
	{
		static const QITAB qit[] =
		{
			QITABENT(CCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
			QITABENT(CCredential, IConnectableCredentialProviderCredential), // IID_IConnectableCredentialProviderCredential
			{ 0 },
		};

		return QISearch(this, qit, riid, ppv);
	}
public:
	// ICredentialProviderCredential
	IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce) override;
	IFACEMETHODIMP UnAdvise() override;

	IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon) override;
	IFACEMETHODIMP SetDeselected() override;

	IFACEMETHODIMP GetFieldState(__in DWORD dwFieldID,
		__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
		__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;

	IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz) override;
	IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp) override;
	IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel) override;
	IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(< , *pcItems) DWORD* pdwSelectedItem) override;
	IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem) override;
	IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo) override;

	IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz) override;
	IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked) override;
	IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem) override;
	IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID) override;

	IFACEMETHODIMP GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

	IFACEMETHODIMP ReportResult(__in NTSTATUS ntsStatus,
		__in NTSTATUS ntsSubstatus,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

public:
	// IConnectableCredentialProviderCredential 
	IFACEMETHODIMP Connect(__in IQueryContinueWithStatus* pqcws) override;
	IFACEMETHODIMP Disconnect() override;

	CCredential(std::shared_ptr<Configuration> c);
	virtual ~CCredential();

public:
	HRESULT Initialize(
		__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
		__in const FIELD_STATE_PAIR* rgfsp,
		__in_opt PWSTR user_name,
		__in_opt PWSTR domain_name,
		__in_opt PWSTR password);

	HRESULT StopPoll();

private:
	HRESULT SetMode(MODE mode);

	HRESULT ResetMode(bool resetToFirstStep = false);

	HRESULT SetDomainHint(std::wstring domain);

	HRESULT SetOfflineInfo(std::string username);

	MODE SelectFIDOMode(std::string userVerification = "", bool offline = false);

	void ShowErrorMessage(const std::wstring& message, const HRESULT& code = 0);

	void PushAuthenticationCallback(const PIResponse& response);

	HBITMAP CreateBitmapFromBase64PNG(const std::wstring& base64);

	bool CheckExcludedAccount();

	HRESULT FIDOAuthentication(IQueryContinueWithStatus* pqcws);
	HRESULT FIDORegistration(IQueryContinueWithStatus* pqcws);

	// Waits until a FIDO2 device is found or the search is cancelled. If the search is cancelled, an empty optional is returned
	// and _fidoDeviceSearchCancelled is set to true.
	// Checks every 200ms if a device is found. Default timeout is 5 minutes.
	std::optional<FIDO2Device> WaitForFIDODevice(IQueryContinueWithStatus* pqcws, int timeoutMs = 300000);

	void HandleFirstStep();

	LONG _cRef;
	// An array holding the type and name of each field in the tile.
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR _rgCredProvFieldDescriptors[FID_NUM_FIELDS];

	// An array holding the state of each field in the tile.
	FIELD_STATE_PAIR _rgFieldStatePairs[FID_NUM_FIELDS];				
	
	// An array holding the string value of each field. This is different from the name of 
	// the field held in _rgCredProvFieldDescriptors.
	wchar_t* _rgFieldStrings[FID_NUM_FIELDS];
	ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;
	DWORD _dwComboIndex;
	PrivacyIDEA	_privacyIDEA;
	std::shared_ptr<Configuration> _config;
	Utilities _util;
	std::wstring _initialDomain;
	HRESULT _lastStatus = S_OK;
	bool _privacyIDEASuccess = false;
	bool _fidoDeviceSearchCancelled = false;
	bool _modeSwitched = false;
	std::optional<FIDO2SignRequest> _passkeyChallenge = std::nullopt;
	bool _passkeyRegistrationFailed = false;
};
