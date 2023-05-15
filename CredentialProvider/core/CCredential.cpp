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

#include "CCredential.h"
#include "Configuration.h"
#include "Logger.h"
#include <resource.h>
#include <string>
#include <thread>
#include <future>
#include <sstream>
#include <RegistryReader.h>
#include <Convert.h>
#include <gdiplus.h>
#pragma comment (lib,"Gdiplus.lib")

using namespace std;

CCredential::CCredential(std::shared_ptr<Configuration> c) :
	_config(c), _util(_config), _privacyIDEA(c->piconfig)
{
	_cRef = 1;
	_pCredProvCredentialEvents = nullptr;

	DllAddRef();

	_dwComboIndex = 0;

	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);
}

CCredential::~CCredential()
{
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
	DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CCredential::Initialize(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
)
{
	DebugPrint(__FUNCTION__);

	wstring wstrUsername, wstrDomainname;
	std::wstring wstrPassword;

	if (NOT_EMPTY(user_name))
	{
		wstrUsername = wstring(user_name);
	}
	if (NOT_EMPTY(domain_name))
	{
		wstrDomainname = wstring(domain_name);
		_initialDomain = wstrDomainname;
	}

	if (NOT_EMPTY(password))
	{
		PWSTR pwzProtectedPassword;
		HRESULT hr = SHStrDupW(password, &pwzProtectedPassword);
		if (SUCCEEDED(hr))
		{
			// If the password is coming from a remote login, it is encrypted and has to be decrypted
			// to be used e.g. for sending it to privacyIDEA prior to the OTP
			// This function does nothing to unencrypted passwords
			hr = UnProtectIfNecessaryAndCopyPassword(pwzProtectedPassword, &password);
			if (FAILED(hr))
			{
				DebugPrint("Failed to decrypt password " + GetLastError());
			}
		}
		CoTaskMemFree(pwzProtectedPassword);
		wstrPassword = std::wstring(password);
	}

	DebugPrint(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	DebugPrint(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));
	if (_config->piconfig.logPasswords)
	{
		DebugPrint(L"Password from provider: " + (wstrPassword.empty() ? L"empty" : wstrPassword));
	}
	HRESULT hr = S_OK;

	if (!wstrUsername.empty())
	{
		_config->credential.username = wstrUsername;
	}

	if (!wstrDomainname.empty())
	{
		_config->credential.domain = wstrDomainname;
	}

	if (!wstrPassword.empty())
	{
		_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		//DebugPrint("Copy field #:");
		//DebugPrint(i + 1);
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		_util.InitializeField(_rgFieldStrings, i);
	}

	DebugPrint("Init result: " + Convert::LongToHexString(hr));

	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(
	__in ICredentialProviderCredentialEvents* pcpce
)
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CCredential::UnAdvise()
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = nullptr;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
	DebugPrint(__FUNCTION__);
	*pbAutoLogon = false;
	HRESULT hr = S_OK;

	if (_config->doAutoLogon)
	{
		*pbAutoLogon = TRUE;
		DebugPrint("AUTOLOGON ENABLED!");
		_config->doAutoLogon = false;
	}

	if (_config->credential.passwordMustChange
		&& _config->provider.cpu == CPUS_UNLOCK_WORKSTATION
		&& _config->winVerMajor != 10)
	{
		// We cant handle a password change while the maschine is locked, so we guide the user to sign out and in again like windows does
		DebugPrint("Password must change in CPUS_UNLOCK_WORKSTATION");
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, L"Go back until you are asked to sign in.");
		_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"To change your password sign out and in again.");
		_pCredProvCredentialEvents->SetFieldState(this, FID_LDAP_PASS, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
	}

	if (_config->credential.passwordMustChange)
	{
		hr = _util.SetScenario(this, _pCredProvCredentialEvents, SCENARIO::CHANGE_PASSWORD);
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
		{
			_config->bypassPrivacyIDEA = true;
		}
	}

	if (_config->prefillUsername)
	{
		RegistryReader rr(LAST_USER_REGISTRY_PATH);
		wstring wszEntry = rr.GetWStringRegistry(L"LastLoggedOnUser");
		wstring wszLastUser = wszEntry.substr(wszEntry.find(L"\\") + 1, wszEntry.length() - 1);
		hr = _pCredProvCredentialEvents->SetFieldString(this, FID_USERNAME, wszLastUser.c_str());
		hr = _pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_LDAP_PASS, CPFIS_FOCUSED);
	}

	if (!_config->showResetLink)
	{
		hr = _pCredProvCredentialEvents->SetFieldState(this, FID_COMMANDLINK, CPFS_HIDDEN);
	}

	// In case of wrong password or other resets, the offline values will be consumed anyway. Therefore update the values remaining.
	if (_config->showOfflineInfo)
	{
		_util.ReadUserField();
		hr = SetOfflineInfo(Convert::ToString(_config->credential.username));
	}

	if (_config->credential.passwordChanged)
	{
		*pbAutoLogon = TRUE;
	}

	return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CCredential::SetDeselected()
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	hr = _util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);

	hr = _util.ResetScenario(this, _pCredProvCredentialEvents);

	// Reset password changing in case another user wants to log in
	_config->credential.passwordChanged = false;
	_config->credential.passwordMustChange = false;

	return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CCredential::GetFieldState(
	__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Validate paramters.
	if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < FID_NUM_FIELDS && ppwsz)
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = nullptr;
		string szPath = Convert::ToString(_config->bitmapPath);
		LPCSTR lpszBitmapPath = szPath.c_str();

		if (NOT_EMPTY(lpszBitmapPath))
		{
			DWORD const dwAttrib = GetFileAttributesA(lpszBitmapPath);

			DebugPrint(dwAttrib);

			if (dwAttrib != INVALID_FILE_ATTRIBUTES
				&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			{
				hbmp = (HBITMAP)LoadImageA(nullptr, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

				if (hbmp == nullptr)
				{
					DebugPrint(GetLastError());
				}
			}
		}

		if (hbmp == nullptr)
		{
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
		}

		if (hbmp != nullptr)
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

	DebugPrint(hr);

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CCredential::GetSubmitButtonValue(
	__in DWORD dwFieldID,
	__out DWORD* pdwAdjacentTo
)
{
	DebugPrint(__FUNCTION__);
	//DebugPrint("Submit Button ID:" + to_string(dwFieldID));
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// This is only called once when the credential is created.
		// When switching to the second step, the button is set via CredentialEvents
		*pdwAdjacentTo = _config->twoStepHideOTP ? FID_LDAP_PASS : FID_OTP;
		return S_OK;
	}
	return E_INVALIDARG;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CCredential::SetStringValue(
	__in DWORD dwFieldID,
	__in PCWSTR pwz
)
{
	HRESULT hr = S_OK;

	// Validate parameters.
	const CREDENTIAL_PROVIDER_FIELD_TYPE fieldType = _rgCredProvFieldDescriptors[dwFieldID].cpft;
	if (dwFieldID < FID_NUM_FIELDS && (CPFT_EDIT_TEXT == fieldType || CPFT_PASSWORD_TEXT == fieldType))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);

		if (dwFieldID == FID_USERNAME)
		{
			// Evaluate the input of FID_USERNAME for domain\user or user@domain input
			wstring input(pwz);
			wstring domain, username;

			Utilities::SplitUserAndDomain(input, username, domain);
			// Set the domain hint to the domain that was found or to the initial domain that was provided
			// when the credential was created
			if (!domain.empty())
			{
				SetDomainHint(domain);
			}
			else
			{
				SetDomainHint(_initialDomain);
				_config->credential.domain = _initialDomain;
			}

			// Set the serial and remaining offline OTPs as hint if the setting is enabled
			// If no offline token are found for the current input, hide the field
			if (_config->showOfflineInfo)
			{
				SetOfflineInfo(Convert::ToString(username));
			}
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT CCredential::SetOfflineInfo(std::string username)
{
	bool infoSet = false;
	HRESULT hr = S_OK;
	if (!username.empty())
	{
		auto offlineInfo = _privacyIDEA.offlineHandler.GetTokenInfo(username);
		if (!offlineInfo.empty())
		{
			wstring message = Utilities::GetTranslatedText(TEXT_AVAILABLE_OFFLINE_TOKEN);
			for (auto& pair : offlineInfo)
			{
				// <serial> (XX OTPs remaining)
				message.append(Convert::ToWString(pair.first)).append(L" (").append(to_wstring(pair.second)).append(L" ")
					.append(Utilities::GetTranslatedText(TEXT_OTPS_REMAINING)).append(L")\n");
			}

			infoSet = true;
			_pCredProvCredentialEvents->SetFieldState(this, FID_OFFLINE_INFO, CPFS_DISPLAY_IN_SELECTED_TILE);
			_pCredProvCredentialEvents->SetFieldString(this, FID_OFFLINE_INFO, message.c_str());
		}
	}

	if (!infoSet)
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_OFFLINE_INFO, CPFS_HIDDEN);
		hr = E_FAIL;
	}
	return hr;
}

HRESULT CCredential::SetDomainHint(std::wstring domain)
{
	if (_config->showDomainHint && !domain.empty())
	{
		wstring text = Utilities::GetTranslatedText(TEXT_DOMAIN_HINT) + domain;
		_pCredProvCredentialEvents->SetFieldString(this, FID_SUBTEXT, text.c_str());
	}
	return S_OK;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the 
// currently selected item (pdwSelectedItem).
HRESULT CCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem
)
{
	DebugPrint(__FUNCTION__);

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		// UNUSED
		*pcItems = 0;
		*pdwSelectedItem = 0;
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID,
	__in DWORD dwItem,
	__deref_out PWSTR* ppwszItem)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);

	return E_INVALIDARG;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(
	__in DWORD dwFieldID,
	__in DWORD dwSelectedItem
)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwSelectedItem);
	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

HRESULT CCredential::GetCheckboxValue(
	__in DWORD dwFieldID,
	__out BOOL* pbChecked,
	__deref_out PWSTR* ppwszLabel
)
{
	// Called to check the initial state of the checkbox
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszLabel);
	*pbChecked = FALSE;
	//SHStrDupW(L"Use offline token.", ppwszLabel); // TODO custom text?

	return S_OK;
}

HRESULT CCredential::SetCheckboxValue(
	__in DWORD dwFieldID,
	__in BOOL bChecked
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);
	DebugPrint(__FUNCTION__);
	return S_OK;
}

HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	DebugPrint(__FUNCTION__);
	_config->isSecondStep = false;
	_privacyIDEA.StopPoll();
	_util.ResetScenario(this, _pCredProvCredentialEvents);
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	return S_OK;
}

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;
	/*
	CPGSR_NO_CREDENTIAL_NOT_FINISHED
	No credential was serialized because more information is needed.

	CPGSR_NO_CREDENTIAL_FINISHED
	This serialization response means that the Credential Provider has not serialized a credential but
	it has completed its work. This response has multiple meanings.
	It can mean that no credential was serialized and the user should not try again.
	This response can also mean no credential was submitted but the credentials work is complete.
	For instance, in the Change Password scenario, this response implies success.

	CPGSR_RETURN_CREDENTIAL_FINISHED
	A credential was serialized. This response implies a serialization structure was passed back.

	CPGSR_RETURN_NO_CREDENTIAL_FINISHED
	The credential provider has not serialized a credential, but has completed its work.
	The difference between this value and CPGSR_NO_CREDENTIAL_FINISHED is that this flag
	will force the logon UI to return, which will unadvise all the credential providers.
	*/
	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	_config->provider.status_icon = pcpsiOptionalStatusIcon;
	_config->provider.status_text = ppwszOptionalStatusText;

	// Do password change
	if (_config->credential.passwordMustChange)
	{
		// Compare new passwords
		if (_config->credential.newPassword1 == _config->credential.newPassword2)
		{
			_util.KerberosChangePassword(pcpgsr, pcpcs, _config->credential.username, _config->credential.password,
				_config->credential.newPassword1, _config->credential.domain);
		}
		else
		{
			// not finished
			ShowErrorMessage(L"New passwords don't match!");
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			_config->clearFields = false;
		}
	}
	else if (_config->credential.passwordChanged)
	{
		// Logon with the new password
		hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
			_config->credential.username, _config->credential.newPassword1, _config->credential.domain);
		_config->credential.passwordChanged = false;
	}
	else
	{
		if (_config->userCanceled)
		{
			*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
			ShowErrorMessage(L"Logon cancelled");
			return S_FALSE;
		}
		// Check if we are pre 2nd step or failure
		if (_authenticationComplete == false && _config->pushAuthenticationSuccessful == false)
		{
			if (_config->isSecondStep == false && _config->twoStepHideOTP && _lastError == S_OK)
			{
				// Prepare for the second step (input only OTP)
				_config->isSecondStep = true;
				_config->clearFields = false;
				_util.SetScenario(this, _pCredProvCredentialEvents, SCENARIO::SECOND_STEP);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			else if (_config->isSecondStep && !_config->lastResponse.challenges.empty())
			{
				// Repeat the second step (privacyIDEA) because another challenge was triggered
				_util.SetScenario(this, _pCredProvCredentialEvents, SCENARIO::SECOND_STEP);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			else
			{
				// Failed authentication or error section - create a message depending on the error
				wstring errorMessage = _config->defaultOTPFailureText;
				if (!_config->lastResponse.errorMessage.empty())
				{
					errorMessage = Convert::ToWString(_config->lastResponse.errorMessage);
				}
				else if (_lastError != S_OK)
				{
					// Probably configuration or network error - details will be logged where the error occurs -> check log
					errorMessage = Utilities::GetTranslatedText(TEXT_GENERIC_ERROR);
				}

				ShowErrorMessage(errorMessage, _config->lastResponse.errorCode);
				// TODO should it reset to first step if OTP is wrong?
				//_config->isSecondStep = false;
				_util.ResetScenario(this, _pCredProvCredentialEvents);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		else if (_authenticationComplete || _config->pushAuthenticationSuccessful)
		{
			// Reset the authentication
			_authenticationComplete = false;
			_config->pushAuthenticationSuccessful = false;
			_privacyIDEA.StopPoll();

			// Pack credentials for logon
			if (_config->provider.cpu == CPUS_CREDUI)
			{
				hr = _util.CredPackAuthentication(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
			else
			{
				hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
		}
		else
		{
			ShowErrorMessage(L"Unexpected error");
			// Reset to first step
			_config->isSecondStep = false;
			_util.ResetScenario(this, _pCredProvCredentialEvents);
			hr = S_FALSE;
		}
	}

	if (_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		_config->clearFields = true; // it's a one-timer...
	}

	if (pcpgsr)
	{
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_FINISHED"); }
		else if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		else if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		else if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { DebugPrint("pcpgsr is a nullpointer!"); }

	DebugPrint("CCredential::GetSerialization - END");
	return hr;
}

// if code == 0, the code won't be displayed
void CCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	*_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	SHStrDupW(errorMessage.c_str(), _config->provider.status_text);
}

// If push is successful, reset the credential to do autologin
void CCredential::PushAuthenticationCallback(bool success)
{
	DebugPrint(__FUNCTION__);
	if (success)
	{
		_config->pushAuthenticationSuccessful = true;
		_config->doAutoLogon = true;
		// When autologon is triggered, connect is called instantly, therefore bypass privacyIDEA on next run
		_config->bypassPrivacyIDEA = true;
		_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
	}
}

// Connect is called first after the submit button is pressed.
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{
	DebugPrint(string(__FUNCTION__) + ": CREDENTIAL SUBMITTED - step " + (_config->isSecondStep ? "2" : "1"));
	UNREFERENCED_PARAMETER(pqcws);
	_lastError = S_OK; // reset error
	_config->provider.field_strings = _rgFieldStrings;
	_util.CopyInputsToConfig();

	wstring username = _config->credential.username;
	wstring domain = _config->credential.domain;
	// Leave the UPN empty if it should not be used
	wstring upn = _config->piconfig.sendUPN ? _config->credential.upn : L"";

	// Check if the user is the excluded account
	if (!_config->excludedAccount.empty())
	{
		wstring toCompare;
		if (!_config->credential.domain.empty())
		{
			toCompare.append(_config->credential.domain).append(L"\\");
		}
		toCompare.append(_config->credential.username);

		// Check if the excluded account from the registry contains '.' and resolve that to the computer name
		wstring exclUsername, exclDomain;
		Utilities::SplitUserAndDomain(_config->excludedAccount, exclUsername, exclDomain);
		wstring exclAccount = exclDomain + L"\\" + exclUsername;
		DebugPrint(L"Matching user with excluded account: " + exclAccount);
		if (Convert::ToUpperCase(toCompare) == Convert::ToUpperCase(exclAccount))
		{
			DebugPrint("Login data matches excluded account, skipping 2FA...");
			// Simulate 2FA success so the logic in GetSerialization can stay the same
			_authenticationComplete = true;
			return S_OK;
		}
	}

	if (_config->bypassPrivacyIDEA)
	{
		DebugPrint("Bypassing privacyIDEA...");
		_config->bypassPrivacyIDEA = false;

		return S_OK;
	}

	// Evaluate if and what should be sent to the server depending on the step and configuration
	bool sendSomething = false, offlineCheck = false;
	wstring passToSend;
	PIResponse piResponse;

	if (_config->twoStepHideOTP && !_config->isSecondStep)
	{
		if (!_config->twoStepSendEmptyPassword && !_config->twoStepSendPassword)
		{
			DebugPrint("1st step: Not sending anything");
			// Delay for a short moment, otherwise logonui freezes (???)
			this_thread::sleep_for(chrono::milliseconds(200));
			// Then skip to next step
		}
		else
		{
			sendSomething = true;
			if (!_config->twoStepSendEmptyPassword && _config->twoStepSendPassword)
			{
				passToSend = _config->credential.password;
				DebugPrint("1st step: Sending windows pass");
			}
			else
			{
				DebugPrint("1st step: Sending empty pass");
			}
		}
	}
	else
	{
		DebugPrint("2nd step: Sending OTP/Offline check");
		// Second step or Single step authentication, actually use the OTP and do offlineCheck before
		passToSend = _config->credential.otp;
		offlineCheck = true;
		sendSomething = true;
	}

	// Do the request
	if (sendSomething)
	{
		HRESULT res = E_FAIL;
		if (offlineCheck)
		{
			string serialUsed;
			res = _privacyIDEA.OfflineCheck(username, passToSend, serialUsed);
			// Check if a OfflineRefill should be attempted. Either if offlineThreshold is not set, remaining OTPs are below the threshold, or no more OTPs are available.
			if ((res == S_OK && _config->offlineTreshold == 0)
				|| (res == S_OK && _privacyIDEA.offlineHandler.GetOfflineOTPCount(Convert::ToString(username), serialUsed) < _config->offlineTreshold)
				|| res == PI_OFFLINE_DATA_NO_OTPS_LEFT)
			{
				const HRESULT refillResult = _privacyIDEA.OfflineRefill(username, passToSend, serialUsed);
				if (refillResult != S_OK)
				{
					DebugPrint("OfflineRefill failed " + Convert::LongToHexString(refillResult));
				}
			}

			// Authentication is complete if offlineCheck succeeds, regardless of refill status
			if (res == S_OK)
			{
				_authenticationComplete = true;
			}
		}

		if (res != S_OK)
		{
			// In case of a single step the transactionId will be an empty string
			string transactionId = _config->lastResponse.transactionId;
			res = _privacyIDEA.ValidateCheck(username, domain, passToSend, piResponse, transactionId, upn);

			// Evaluate the response
			if (SUCCEEDED(res))
			{
				_config->lastResponse = piResponse;
				// Always show the OTP field, if push was triggered, start polling in background
				if (piResponse.PushAvailable())
				{
					// When polling finishes, pushAuthenticationCallback is invoked with the finalization success value
					_privacyIDEA.PollTransactionAsync(username, domain, upn, piResponse.transactionId,
						std::bind(&CCredential::PushAuthenticationCallback, this, std::placeholders::_1));
				}

				if (!piResponse.challenges.empty())
				{
					DebugPrint("Challenges have been triggered");

					// Only one image can be displayed so take the first challenge
					// In the main use-case, token enrollment, there will only be a single challenge
					// because the enrollment is only happening after the authentication is completed
					if (piResponse.challenges.size() >= 1)
					{
						auto& challenge = piResponse.challenges.at(0);
						if (!challenge.image.empty())
						{
							// Remove the leading "data:image/png;base64,"
							auto base64image = challenge.image.substr(22, challenge.image.size());
							if (!base64image.empty())
							{
								auto hBitmap = CreateBitmapFromBase64PNG(Convert::ToWString(base64image));
								if (hBitmap != nullptr)
								{
									_pCredProvCredentialEvents->SetFieldBitmap(this, FID_LOGO, hBitmap);
								}
								else
								{
									DebugPrint("Conversion to bitmap failed, image will not be displayed.");
								}
							}
						}
					}

					_authenticationComplete = false;
				}
				else
				{
					_authenticationComplete = piResponse.value;
				}
			}
			else
			{
				// If an error occured during the first step (send pw/empty) ignore it
				// so the next step, where offline could be done, will still be possible
				if (_config->twoStepHideOTP && !_config->isSecondStep)
				{
					_lastError = S_OK;
				}
				else
				{
					_lastError = res;
				}
			}
		}
	}

	DebugPrint("Authentication complete: " + Convert::ToString(_authenticationComplete));
	DebugPrint("Connect - END");
	return S_OK;
}

HBITMAP CCredential::CreateBitmapFromBase64PNG(const std::wstring& base64)
{
	std::vector<BYTE> binaryData;
	DWORD binaryDataSize = 0;
	if (!CryptStringToBinary(base64.c_str(), base64.size(), CRYPT_STRING_BASE64, nullptr, &binaryDataSize, nullptr, nullptr))
	{
		return nullptr;
	}
	binaryData.resize(binaryDataSize);
	if (!CryptStringToBinary(base64.c_str(), base64.size(), CRYPT_STRING_BASE64, binaryData.data(), &binaryDataSize, nullptr, nullptr))
	{
		return nullptr;
	}

	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	IStream* stream = NULL;
	CreateStreamOnHGlobal(NULL, TRUE, &stream);
	stream->Write(binaryData.data(), binaryDataSize, NULL);
	Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromStream(stream);
	HBITMAP hBitmap;
	auto status = bitmap->GetHBITMAP(Gdiplus::Color::White, &hBitmap);
	if (status != Gdiplus::Status::Ok)
	{
		Print("Getting bitmap failed, gdiplus status: " + to_string(status));
		hBitmap = nullptr;
	}
	delete bitmap;
	stream->Release();
	Gdiplus::GdiplusShutdown(gdiplusToken);
	return hBitmap;
}

HRESULT CCredential::Disconnect()
{
	return E_NOTIMPL;
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);
	DebugPrint("ntsStatus: " + Convert::LongToHexString(ntsStatus)
		+ ", ntsSubstatus: " + Convert::LongToHexString(ntsSubstatus));

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	// These status require a complete reset so that there will be no lock out in 2nd step
	if (ntsStatus == STATUS_LOGON_FAILURE || ntsStatus == STATUS_LOGON_TYPE_NOT_GRANTED
		|| ntsStatus == STATUS_ACCOUNT_RESTRICTION)
	{
		DebugPrint("Complete reset!");
		_authenticationComplete = false;
		_config->isSecondStep = false;
		_util.ResetScenario(this, _pCredProvCredentialEvents);
		return S_OK;
	}

	if (_config->credential.passwordMustChange && ntsStatus == 0 && ntsSubstatus == 0)
	{
		// Password change was successful, set this so SetSelected knows to autologon
		_config->credential.passwordMustChange = false;
		_config->credential.passwordChanged = true;
		_util.ResetScenario(this, _pCredProvCredentialEvents);
		return S_OK;
	}

	bool const pwMustChange = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) || (ntsSubstatus == STATUS_PASSWORD_EXPIRED);
	if (pwMustChange)
	{
		_config->credential.passwordMustChange = true;
		DebugPrint("Status: Password must change");
		return S_OK;
	}

	// check if the password update was NOT successfull
	// these two are for new passwords not conform to password policies
	bool pwNotUpdated = (ntsStatus == STATUS_PASSWORD_RESTRICTION) || (ntsSubstatus == STATUS_ILL_FORMED_PASSWORD);
	if (pwNotUpdated)
	{
		DebugPrint("Status: Password update failed: Not conform to policies");
	}
	// this catches the wrong old password 
	pwNotUpdated = pwNotUpdated || ((ntsStatus == STATUS_LOGON_FAILURE) && (ntsSubstatus == STATUS_INTERNAL_ERROR));

	if (pwNotUpdated)
	{
		// it wasn't updated so we start over again
		_config->credential.passwordMustChange = true;
		_config->credential.passwordChanged = false;
	}

	//_util.ResetScenario(this, _pCredProvCredentialEvents);
	return S_OK;
}
