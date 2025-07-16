/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2025 NetKnights GmbH
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
#include <resource.h>
#include <string>
#include <thread>
#include <future>
#include <sstream>

#include "CCredential.h"
#include "Configuration.h"
#include "RegistryReader.h"
#include "Convert.h"
#include "Logger.h"
#include "WebAuthn.h"
#include "DeviceNotification.h"
#include "FIDODevice.h"
#include "SmartcardListener.h"
#include "FIDOException.h"
#include "Mode.h"
#include <lm.h>
#include <gdiplus.h>
#pragma comment (lib, "Gdiplus.lib")
#pragma comment(lib, "Netapi32.lib")

const std::wstring IMAGE_BASE64_PREFIX = L"data:image/png;base64,";

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
	__in_opt PWSTR userName,
	__in_opt PWSTR domainName,
	__in_opt PWSTR password
)
{
	PIDebug(__FUNCTION__);

	wstring wstrUsername, wstrDomainname;
	std::wstring wstrPassword;
	HRESULT hr = S_OK;

	if (NOT_EMPTY(userName))
	{
		wstrUsername = wstring(userName);
	}
	if (NOT_EMPTY(domainName))
	{
		wstrDomainname = wstring(domainName);
		_initialDomain = wstrDomainname;
	}

	if (NOT_EMPTY(password))
	{
		PWSTR pwzProtectedPassword;
		hr = SHStrDupW(password, &pwzProtectedPassword);
		if (SUCCEEDED(hr))
		{
			// If the password is coming from a remote login, it is encrypted and has to be decrypted
			// to be used e.g. for sending it to privacyIDEA prior to the OTP
			// This function does nothing to unencrypted passwords
			hr = UnProtectIfNecessaryAndCopyPassword(pwzProtectedPassword, &password);
			if (FAILED(hr))
			{
				PIDebug("Failed to decrypt password " + GetLastError());
			}
		}
		CoTaskMemFree(pwzProtectedPassword);
		wstrPassword = std::wstring(password);
	}

	PIDebug(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	PIDebug(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));
	if (_config->piconfig.logPasswords)
	{
		PIDebug(L"Password from provider: " + (wstrPassword.empty() ? L"empty" : wstrPassword));
	}


	// Check if the username is in UPN format. In that case we do not need the domain name.
	// Otherwise, use the user and domain name from the provider.
	wstring tmpUser, tmpDomain;
	Utilities::SplitUserAndDomain(wstrUsername, tmpUser, tmpDomain);
	if (!tmpDomain.empty())
	{
		PIDebug(L"Username is in UPN format, using domain from username");
		_config->credential.username = tmpUser;
		_config->credential.domain = tmpDomain;
	}
	else
	{
		PIDebug(L"Username is not in UPN format, using username and domain from provider");
		if (!wstrUsername.empty())
		{
			_config->credential.username = wstrUsername;
		}

		if (!wstrDomainname.empty())
		{
			_config->credential.domain = wstrDomainname;
		}
	}

	if (!wstrPassword.empty())
	{
		_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		hr = _util.InitializeField(_rgFieldStrings, i);
		if (FAILED(hr))
		{
			PIError("Failed to initialize field " + to_string(i));
		}
	}

	PIDebug("Init result: " + Convert::LongToHexString(hr));
	return hr;
}

HRESULT CCredential::StopPoll()
{
	_privacyIDEA.StopPoll();
	return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(
	__in ICredentialProviderCredentialEvents* pcpce
)
{
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
	PIDebug("CCredential::SetSelected Mode=" + _config->ModeString());
	*pbAutoLogon = false;
	HRESULT hr = S_OK;

	if (_config->doAutoLogon)
	{
		// If auto login is enabled, something has happened before, so do not change the mode!
		*pbAutoLogon = TRUE;
		PIDebug("AUTOLOGON ENABLED!");
		_config->doAutoLogon = false;
	}
	else
	{
		// This is the initial setup, setting the mode etc.
		if (_config->credential.passwordMustChange
			&& _config->provider.cpu == CPUS_UNLOCK_WORKSTATION
			&& _config->winVerMajor != 10)
		{
			// We cant handle a password change while the machine is locked, so we guide the user to sign
			// out and in again like windows does
			PIDebug("Password must change in CPUS_UNLOCK_WORKSTATION");
			_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, L"Go back until you are asked to sign in.");
			_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"To change your password, sign out and in again.");
			_pCredProvCredentialEvents->SetFieldState(this, FID_PASSWORD, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
		}
		else if (_config->credential.passwordMustChange)
		{
			hr = SetMode(Mode::CHANGE_PASSWORD);
			if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
			{
				_config->bypassPrivacyIDEA = true;
			}
		}
		else
		{
			// Only set the mode intially. Afterwards, keep the mode
			if (_config->isFirstStep())
			{
				hr = SetMode(_config->GetFirstStepMode());
			}
		}
	}

	// Do not prefill the username if auto logon is enabled. In that case, the username that has been entered should be used.
	if (_config->prefillUsername && !*pbAutoLogon)
	{
		RegistryReader rr(LAST_USER_REGISTRY_PATH);
		wstring wszEntry = rr.GetWString(L"LastLoggedOnUser");
		wstring wszLastUser = wszEntry.substr(wszEntry.find(L"\\") + 1, wszEntry.length() - 1);
		hr = _pCredProvCredentialEvents->SetFieldString(this, FID_USERNAME, wszLastUser.c_str());
		hr = _pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_FOCUSED);
	}

	/*
	if (_config->showResetLink)
	{
		hr = _pCredProvCredentialEvents->SetFieldState(this, FID_RESET_LINK, CPFS_DISPLAY_IN_SELECTED_TILE);
	}
	*/
	// In case of wrong password or other resets, the offline values will be consumed anyway. Therefore update the values remaining.
	if (_config->offlineShowInfo)
	{
		_util.CopyUsernameField();
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
	PIDebug(__FUNCTION__);

	HRESULT hr = S_OK;

	hr = _util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);
	hr = SetOfflineInfo("");
	hr = ResetMode();
	_config->credential.domain = L"";
	_config->credential.username = L"";
	_config->credential.password = L"";
	_config->lastTransactionId = "";
	// Reset password changing in case another user wants to log in
	_config->credential.passwordChanged = false;
	_config->credential.passwordMustChange = false;
	// Possible cleanup
	DeviceNotification::Unregister();

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
	HRESULT hr = S_OK;

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

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
)
{
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

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
)
{
	PIDebug(__FUNCTION__);

	*phbmp = nullptr;
	return S_OK;
	/*
	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = nullptr;
		string szPath = Convert::ToString(_config->bitmapPath);
		LPCSTR lpszBitmapPath = szPath.c_str();

		if (NOT_EMPTY(lpszBitmapPath))
		{
			DWORD const dwAttrib = GetFileAttributesA(lpszBitmapPath);

			PIDebug(dwAttrib);

			if (dwAttrib != INVALID_FILE_ATTRIBUTES
				&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			{
				hbmp = (HBITMAP)LoadImageA(nullptr, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

				if (hbmp == nullptr)
				{
					PIDebug(GetLastError());
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

	PIDebug(hr);

	return hr;
	*/
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
	PIDebug(__FUNCTION__);
	//PIDebug("Submit Button ID:" + to_string(dwFieldID));
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// This is only called once when the credential is created.
		// When switching to the second step, the button is set via CredentialEvents
		*pdwAdjacentTo = FID_USERNAME;
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

	const CREDENTIAL_PROVIDER_FIELD_TYPE fieldType = _rgCredProvFieldDescriptors[dwFieldID].cpft;
	if (dwFieldID < FID_NUM_FIELDS && (CPFT_EDIT_TEXT == fieldType || CPFT_PASSWORD_TEXT == fieldType))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);

		if (dwFieldID == FID_USERNAME)
		{
			wstring input(pwz);
			// Write the value back to the field so that changes from elsewhere (e.g. prefill_username) are overwritten
			_pCredProvCredentialEvents->SetFieldString(this, FID_USERNAME, pwz);
			// Evaluate the input of FID_USERNAME for domain\user or user@domain input
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
			if (_config->offlineShowInfo)
			{
				SetOfflineInfo(Convert::ToString(username));
			}

			/*
			// Check if offline webauthn is available for the user and if so, show the link
			// TODO indicate offline by suffixing the link text?
			if (!_privacyIDEA.offlineHandler.GetWebAuthnOfflineData(Convert::ToString(username)).empty())
			{
				_pCredProvCredentialEvents->SetFieldState(this, FID_WAN_LINK, CPFS_DISPLAY_IN_SELECTED_TILE);
				PIDebug("Enabling WebAuthn link because of available offline data");
			}
			else
			{
				// Disable if no match for the user and no "online" webauthn request
				if (_config->lastResponse.GetWebAuthnSignRequest().allowCredentials.size() > 0)
				{
					_pCredProvCredentialEvents->SetFieldState(this, FID_WAN_LINK, CPFS_HIDDEN);
				}
			}
			*/
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
			wstring message = _util.GetText(TEXT_AVAILABLE_OFFLINE_TOKEN);
			for (auto& pair : offlineInfo)
			{
				if (pair.first.rfind("WAN", 0) == 0 || pair.first.rfind("PIPK", 0) == 0)
				{
					// <serial> (FIDO2)
					message.append(Convert::ToWString(pair.first)).append(L" (FIDO2)\n");
				}
				else
				{
					// <serial> (XX OTPs remaining)
					message.append(Convert::ToWString(pair.first)).append(L" (").append(to_wstring(pair.second)).append(L" ")
						.append(_util.GetText(TEXT_OTPS_REMAINING)).append(L")\n");
				}
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

// Determine the status of FIDO2 devices, the local config and the last response from privacyidea to return the mode based on that.
// It can be one of the following:
// - Mode::SEC_KEY_PIN
// - Mode::SEC_KEY_NO_PIN
// - Mode::SEC_KEY_NO_DEVICE
Mode CCredential::SelectFIDOMode(std::string userVerification, bool offline)
{
	PIDebug(__FUNCTION__);
	bool uvDiscouraged = false;

	if (userVerification.empty())
	{
		if (_config->lastResponse && _config->lastResponse->GetFIDOSignRequest())
		{
			offline = false;
			uvDiscouraged = _config->lastResponse->GetFIDOSignRequest()->userVerification == "discouraged";
		}
		else
		{
			offline = true;
		}
	}
	else
	{
		uvDiscouraged = userVerification == "discouraged";
	}

	auto devices = FIDODevice::GetDevices();

	if (devices.size() == 0)
	{
		PIDebug("No FIDO2 devices found");
		return Mode::SEC_KEY_NO_DEVICE;
	}
	else if (devices.size() > 0)
	{
		if (devices.size() > 1)
		{
			PIDebug("Multiple FIDO2 devices found, using the first: " + devices[0].GetPath());
		}

		if (devices[0].HasPin() && ((!uvDiscouraged && !offline) || (!_config->webAuthnOfflineNoPIN && offline)))
		{
			return Mode::SEC_KEY_PIN;
		}
		else
		{
			return Mode::SEC_KEY_NO_PIN;
		}
	}
	return Mode::NO_CHANGE;
}

HRESULT CCredential::SetMode(Mode mode)
{
	PIDebug("SetMode: " + _config->ModeString() + ", passkey=" + to_string(_config->usePasskey) + ", offlineFIDO=" + to_string(_config->useOfflineFIDO));
	HRESULT hr = S_OK;
	const Mode oldMode = _config->mode;
	if (mode != Mode::NO_CHANGE)
	{
		_config->mode = mode;
	}

	// Reset some field states
	_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_ONLINE, CPFS_HIDDEN);
	_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, CPFS_HIDDEN);

	// Small text is used to display a prompt to the user, like "Please enter your username" or the message of 
	// the last server response.
	wstring smallText;

	switch (mode)
	{
		case Mode::USERNAME:
		{
			// Set the submit button next to the username field
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_USERNAME);
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioUsername);
			smallText = _util.GetText(TEXT_ENTER_USERNAME);
			// Since this is the first step and there is no user, use the login text instead of username
			break;
		}
		case Mode::PASSWORD:
		{
			// Set the submit button next to the password field
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_PASSWORD);
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioPassword);
			smallText = _util.GetText(TEXT_ENTER_PASSWORD);
			break;
		}
		case Mode::USERNAMEPASSWORD:
		{
			// Set the submit button next to the password field
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_PASSWORD);
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioUsernamePassword);
			// Since this is the first step and there is no user, use the login text instead of username
			smallText = _util.GetText(TEXT_ENTER_USERNAME_PASSWORD);
			break;
		}
		case Mode::PRIVACYIDEA:
		{
			// Set the submit button next to the OTP field
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_OTP);
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioPrivacyIDEA);
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_WEBAUTHN).c_str());

			// Only set the message of the last server response if that response has challenges or errors.
			// If hide_first_step_response is enabled, show the default message, but only when coming from the first step.
			if (_config->lastResponse && !_config->lastResponse->message.empty() && !_config->lastResponse->isAuthenticationSuccessful()
				&& (!_config->hideFirstStepResponse && IsModeOneOf(oldMode, Mode::USERNAME, Mode::USERNAMEPASSWORD)))
			{
				smallText = Convert::ToWString(_config->lastResponse->GetDeduplicatedMessage());
			}
			else
			{
				smallText = _util.GetText(TEXT_OTP_PROMPT);
			}
			break;
		}
		case Mode::CHANGE_PASSWORD:
		{
			// Set the submit button next to the repeat pw field
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_NEW_PASS_2);
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioPasswordChange);
			// Show username in large text, prefill old password
			_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, _config->credential.username.c_str());
			_pCredProvCredentialEvents->SetFieldString(this, FID_PASSWORD, _config->credential.password.c_str());
			break;
		}
		// The following are pretty much the same, disabling fido links is below this switch
		case Mode::SEC_KEY_REG_PIN:
			if (_lastStatus == FIDO_ERR_PIN_INVALID)
			{
				smallText = _util.GetText(TEXT_FIDO_ERR_PIN_INVALID);
			}
			else
			{
				smallText = _util.GetText(TEXT_PASSKEY_REGISTRATION) + L". " + _util.GetText(TEXT_SEC_KEY_ENTER_PIN_PROMPT);
			}
			[[fallthrough]];
		case Mode::SEC_KEY_REG:
			[[fallthrough]];
		case Mode::SEC_KEY_PIN:
		{
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioSecurityKey);
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_WAN_PIN);
			_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_WAN_PIN, CPFIS_FOCUSED);
			if (_config->usePasskey)
			{
				_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_LOGIN_WITH_USERNAME).c_str());
			}
			else
			{
				_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_OTP).c_str());
			}
			break;
		}
		case Mode::SEC_KEY_NO_DEVICE:
		{
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioSecurityKey);
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_WAN_PIN);
			_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_WAN_PIN, CPFIS_FOCUSED);
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_OTP).c_str());
			break;
		}
		case Mode::SEC_KEY_NO_PIN:
		{
			hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, s_rgScenarioSecurityKey);
			_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, FID_WAN_PIN);
			_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_WAN_PIN, CPFIS_NONE);
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_OTP).c_str());
			break;
		}
		case Mode::NO_CHANGE:
			break;
		default:
			PIError("SetMode: Unknown mode");
			break;
	}

	_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_OFFLINE, L"Offline FIDO"); // TODO configurable text

	// Large text is used to display the username that is currently loggin in like username@domain
	// There are also settings to hide this, making it either username or nothing.
	wstring largeText;
	if (!_config->credential.username.empty())
	{
		largeText = _config->credential.username;
	}
	if (!_config->credential.domain.empty() && !largeText.empty())
	{
		largeText.append(L"@").append(_config->credential.domain);
	}
	if (_config->hideDomainName)
	{
		largeText = _config->credential.username;
	}
	if (_config->hideFullName)
	{
		largeText = L"";
	}
	// Default if none of the above is used
	if (largeText.empty())
	{
		largeText = _config->loginText;
	}

	if (!largeText.empty())
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, largeText.c_str());
		PIDebug(L"Setting large text: " + largeText);
	}
	else
	{
		PIDebug("Large text is empty, hiding it");
		_pCredProvCredentialEvents->SetFieldState(this, FID_LARGE_TEXT, CPFS_HIDDEN);
	}
	// Small Text set
	if (!smallText.empty())
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, smallText.c_str());
		PIDebug(L"Setting small text: " + smallText);
	}
	else
	{
		PIDebug("Small text is empty, hiding it");
		_pCredProvCredentialEvents->SetFieldState(this, FID_SMALL_TEXT, CPFS_HIDDEN);
	}

	// If the username is already present (e.g. retry after wrong password) focus the password field
	wstring input;
	if (_config != nullptr && _config->provider.field_strings != nullptr)
	{
		input = wstring(_config->provider.field_strings[FID_USERNAME]);
	}

	if (!input.empty())
	{
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_FOCUSED);
	}

	// Domain in FID_SUBTEXT, optional
	if (_config->showDomainHint)
	{
		wstring domaintext = _util.GetText(TEXT_DOMAIN_HINT) + _config->credential.domain;
		_pCredProvCredentialEvents->SetFieldString(this, FID_SUBTEXT, domaintext.c_str());
	}
	else
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_SUBTEXT, CPFS_HIDDEN);
	}

	// WebAuthn/Passkey Link: 
	// In the first step, offer passkey login
	// If a sign request is present or if offline webauthn is available for the user
	bool enableFIDOOnline = mode > Mode::SEC_KEY_ANY;
	// Passkey
	if (_config->isFirstStep() && !_config->disablePasskey)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_PASSKEY).c_str());
		enableFIDOOnline = true;
		PIDebug("Enabling fido online link to offer passkey in first step");
	}

	// FIDO Online
	if (_config->lastResponse && _config->lastResponse->GetFIDOSignRequest())
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_ONLINE, CPFS_DISPLAY_IN_SELECTED_TILE);
		enableFIDOOnline = true;
		PIDebug("Enabling fido online link because of present sign request (challenge triggered)");
	}

	if (enableFIDOOnline)
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_ONLINE, CPFS_DISPLAY_IN_SELECTED_TILE);
	}

	// FIDO Offline TODO when to show the link? only first step?
	auto fidoOfflineData = _privacyIDEA.offlineHandler.GetAllFIDOData();
	if (!fidoOfflineData.empty())
	{
		PIDebug("Enabling offline fido link because there is offline data");
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, CPFS_DISPLAY_IN_SELECTED_TILE);
	}
	else if (!_privacyIDEA.offlineHandler.GetFIDODataFor(Convert::ToString(_config->credential.username)).empty()
		&& _config->isFirstStep())
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, CPFS_DISPLAY_IN_SELECTED_TILE);
		PIDebug("Enabling offline fido link for user");
	}

	// Reset Link: Do not show in first step for both passkey and username/password mode
	if (_config->showResetLink && !_config->isFirstStep() && !(_config->usePasskey && _config->mode > Mode::SEC_KEY_ANY))
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_RESET_LINK, CPFS_DISPLAY_IN_SELECTED_TILE);
	}

	// Offline Info
	if (_config->offlineShowInfo)
	{
		PWSTR pwszUsername;
		this->GetStringValue(FID_USERNAME, &pwszUsername);
		SetOfflineInfo(Convert::ToString(wstring(pwszUsername)));
	}

	// Overwriting previous thing by disabling stuff
	if (_config->ModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN))
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_ONLINE, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OFFLINE_INFO, CPFS_HIDDEN);
	}
	// If its the last step, password, there is no need for offline info or fido2 offline anymore
	if (mode == Mode::PASSWORD)
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_OFFLINE_INFO, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, CPFS_HIDDEN);
	}

	// CredUI no image setting
	/*
	if (_config->credui_no_image && _config->provider.cpu == CPUS_CREDUI)
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_LOGO, CPFS_HIDDEN);
		PIDebug("Hiding logo because of credui_no_image setting");
	}
	else
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_LOGO, CPFS_DISPLAY_IN_BOTH);
	}
	*/
	return hr;
}

HRESULT CCredential::Reset()
{
	PIDebug(__FUNCTION__);
	HRESULT res = S_OK;
	// Reset the credential to the initial state, clearing all fields and resetting the mode.
	StopPoll();
	_config->lastResponse = {};
	_config->lastTransactionId = "";
	if (_pCredProvCredentialEvents != nullptr)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);
		if (_config->twoStepSendPassword || _config->usernamePassword)
		{
			res = SetMode(Mode::USERNAMEPASSWORD);
		}
		else
		{
			res = SetMode(Mode::USERNAME);
		}
	}
	// TODO
	return res;
}

/// <summary>
/// Resets the credential provider's mode, optionally to the first step, and clears relevant fields as needed. If resetToFirstStep is true,
/// the last response and transaction ID are cleared, and the mode is set to the first step.
/// </summary>
/// <param name="resetToFirstStep">If true, resets the mode to the first step regardless of the current mode; otherwise, restores the previous or default mode.</param>
/// <returns>Returns S_OK on success, or an HRESULT error code on failure.</returns>
HRESULT CCredential::ResetMode(__in bool resetToFirstStep)
{
	PIDebug(__FUNCTION__);
	_privacyIDEA.StopPoll();
	// If resetToFirstStep is true, the mode is reset to the first step regardless of the current mode.
	if (resetToFirstStep)
	{
		SetMode(_config->isPasswordInFirstStep() ? Mode::USERNAMEPASSWORD : Mode::USERNAME);
		_config->credential.username = L"";
		_config->credential.password = L"";
		_config->credential.domain = _initialDomain;
		_config->lastTransactionId = "";
		_config->lastResponse = std::nullopt;
	}
	else if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
	{
		SetMode(Mode::USERNAMEPASSWORD);
	}
	else
	{
		SetMode(_config->mode);
	}

	// Do not clear the password for remote sessions, because it is already checked when initializing the remote connection.
	// The OTP field content has to be cleared manually.
	if (_config->isRemoteSession)
	{
		_config->clearFields = false;
		_pCredProvCredentialEvents->SetFieldString(this, FID_OTP, L"");
	}

	return S_OK;
}

HRESULT CCredential::SetDomainHint(std::wstring domain)
{
	if (_config->showDomainHint && !domain.empty())
	{
		wstring text = _util.GetText(TEXT_DOMAIN_HINT) + domain;
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
	PIDebug(__FUNCTION__);

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
HRESULT CCredential::GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem)
{
	PIDebug(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);

	return E_INVALIDARG;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
	PIDebug(__FUNCTION__);
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

HRESULT CCredential::GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel)
{
	// Called to check the initial state of the checkbox
	//PIDebug(__FUNCTION__);
	UNREFERENCED_PARAMETER(ppwszLabel);
	UNREFERENCED_PARAMETER(pbChecked);
	UNREFERENCED_PARAMETER(dwFieldID);
	//SHStrDupW(L"Use Offline FIDO2", ppwszLabel); 

	return S_OK;
}

HRESULT CCredential::SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked)
{
	//PIDebug(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);
	return S_OK;
}

HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	PIDebug(__FUNCTION__);
	if (dwFieldID == FID_RESET_LINK)
	{
		PIDebug("Reset link clicked");
		_privacyIDEA.StopPoll();
		ResetMode(true);
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else if (dwFieldID == FID_FIDO_ONLINE || dwFieldID == FID_FIDO_OFFLINE)
	{
		// Switchting between FIDO and OTP modes in the privacyIDEA step
		// Can also be passkey <-> username(/password) if it is the first step
		_config->useOfflineFIDO = dwFieldID == FID_FIDO_OFFLINE;
		string uv;
		bool offline = false;

		// Passkey
		if (_config->isFirstStep() && !_config->useOfflineFIDO)
		{
			PIDebug("CommandLinkClicked: Passkey Online");
			// Passkey: We need to get the challenge here to have the uv which will decide the 
			// next mode, with or without PIN
			_config->usePasskey = true;
			PIResponse res;
			const auto hr = _privacyIDEA.ValidateInitialize(res);
			if (FAILED(hr) || !res.passkeyChallenge)
			{
				// TODO ERROR
				return S_OK;
			}
			_passkeyChallenge = res.passkeyChallenge.value();
			uv = _passkeyChallenge.value().userVerification;
		}
		// FIDO Offline
		else if (_config->isFirstStep() && _config->useOfflineFIDO)
		{
			uv = _config->webAuthnOfflineNoPIN ? "discouraged" : "required";
			offline = true;
			PIDebug("CommandLinkClicked: FIDO Offline with uv=" + uv);
		}
		// FIDO to OTP or Username/Password
		else if (_config->mode > Mode::SEC_KEY_ANY)
		{
			if (!_config->usePasskey)
			{
				PIDebug("Switching to OTP mode");
				SetMode(Mode::PRIVACYIDEA);
				return S_OK;
			}
			else
			{
				PIDebug("Switching to username/password mode");
				SetMode(_config->GetFirstStepMode());
				_config->usePasskey = false;
				_passkeyChallenge = std::nullopt;
				return S_OK;
			}
		}
		else
		{
			_modeSwitched = true;
			PIDebug("Switching to security key mode");
		}

		const auto mode = SelectFIDOMode(uv, offline);
		SetMode(mode);
		if (mode == Mode::SEC_KEY_NO_DEVICE || mode == Mode::SEC_KEY_NO_PIN)
		{
			_config->doAutoLogon = true;
			_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
		}
	}

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
	PIDebug("CCredential::GetSerialization Mode=" + _config->ModeString() + ", lastStatus=" + to_string(_lastStatus));
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

	// Password change evaluation
	if (_config->credential.passwordMustChange)
	{
		if (_config->credential.newPassword1 == _config->credential.newPassword2)
		{
			_util.KerberosChangePassword(pcpgsr, pcpcs, _config->credential.username, _config->credential.password,
				_config->credential.newPassword1, _config->credential.domain);
		}
		else
		{
			ShowErrorMessage(L"New passwords don't match!");
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			_config->clearFields = false;
		}
	}
	// Logon after pw change with the new pw
	else if (_config->credential.passwordChanged)
	{
		hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
			_config->credential.username, _config->credential.newPassword1, _config->credential.domain);
		_config->credential.passwordChanged = false;
	}
	// Normal authentication: Username, Password, PrivacyIDEA
	else
	{
		// PrivacyIDEA
		if (_privacyIDEASuccess == false && _config->pushAuthenticationSuccess == false)
		{
			auto& lastResponse = _config->lastResponse;

			// Continue with WebAuthn as the second step if there is a sign request and it is configured to be preferred
			// or if the current mode is a webauthn one, e.g. to do NO_DEVICE -> PIN
			const bool offlineWANAvailable = !_privacyIDEA.offlineHandler.GetFIDODataFor(
				Convert::ToString(_config->credential.username)).empty();

			// Continue with webauthn in the following cases:
			// privacyIDEA says so with the preferred_client_mode, or the local setting is set and there is a sign request,
			// or when continuing webauthn (e.g. from NO_DEVICE to PIN)
			bool continueWithWebAuthn = false;
			if (lastResponse)
			{
				continueWithWebAuthn = lastResponse->preferredMode == "webauthn"
					|| (_config->webAuthnPreferred && (lastResponse->GetFIDOSignRequest()
						|| offlineWANAvailable)) || (_config->mode > Mode::SEC_KEY_ANY);
			}

			// If the user cancelled the operation, do not continue with webauthn
			if (_fidoDeviceSearchCancelled)
			{
				continueWithWebAuthn = false;
				_fidoDeviceSearchCancelled = false;
			}

			// Regular second step, asking for second factor. Can also be that the mode was switched (WebAuthn <-> OTP)
			if ((_config->mode == Mode::USERNAME || _config->mode == Mode::USERNAMEPASSWORD)
				&& _lastStatus == S_OK || _modeSwitched)
			{
				PIDebug("Regular second step, asking for second factor");
				_modeSwitched = false;
				_config->clearFields = false;
				SetMode(continueWithWebAuthn ? SelectFIDOMode() : Mode::PRIVACYIDEA);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				if (continueWithWebAuthn && SelectFIDOMode() == Mode::SEC_KEY_NO_DEVICE)
				{
					_config->doAutoLogon = true;
					_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
				}
			}
			// Another challenge was triggered: repeat the privacyidea step
			else if (lastResponse && !lastResponse->challenges.empty() && _lastStatus == S_OK)
			{
				PIDebug("Another challenge was triggered, repeating privacyidea step");
				SetMode(continueWithWebAuthn ? SelectFIDOMode() : Mode::PRIVACYIDEA);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			// Passkey Registration
			else if (lastResponse && lastResponse->passkeyRegistration && _lastStatus == S_OK)
			{
				// Go to Connect() directly for the first time
				if (!_passkeyRegistrationFailed && !_config->ModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN))
				{
					SetMode(Mode::SEC_KEY_REG);
					_config->doAutoLogon = true;
					_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
				}
				else if (_config->ModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN))
				{
					// continue in this mode
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
			}
			// Show an error message if authentication failed or there is an error
			else if (_lastStatus != S_OK || (lastResponse && lastResponse->challenges.empty() && !lastResponse->value &&
				_config->mode >= Mode::PRIVACYIDEA))
			{
				bool resetToFirstStep = false;
				wstring errorMessage = _util.GetText(TEXT_WRONG_OTP);
				if (lastResponse && !lastResponse->errorMessage.empty())
				{
					errorMessage = Convert::ToWString(lastResponse->errorMessage);
				}
				else if (_lastStatus == FIDO_ERR_NO_CREDENTIALS)
				{
					SetMode(Mode::PRIVACYIDEA);
					errorMessage = _util.GetText(TEXT_FIDO_NO_CREDENTIALS);
				}
				else if (_lastStatus == FIDO_ERR_PIN_AUTH_BLOCKED)
				{
					errorMessage = _util.GetText(TEXT_FIDO_ERR_PIN_BLOCKED);
					// If userVerificiation is discouraged, reset to the first step, otherwise there will be an infinite loop
					// of directly retrying because no PIN is requested.
					if (lastResponse && lastResponse->GetFIDOSignRequest()
						&& lastResponse->GetFIDOSignRequest()->userVerification == "discouraged")
					{
						resetToFirstStep = true;
					}
				}
				else if (_lastStatus == FIDO_DEVICE_ERR_TX)
				{
					resetToFirstStep = true;
					errorMessage = _util.GetText(TEXT_FIDO_ERR_TX);
				}
				else if (_lastStatus == FIDO_ERR_PIN_INVALID)
				{
					errorMessage = _util.GetText(TEXT_FIDO_ERR_PIN_INVALID);
				}
				else if (_lastStatus != S_OK)
				{
					// Probably configuration or network error - details will be logged where the error occurs -> check log
					errorMessage = _util.GetText(TEXT_GENERIC_ERROR);
				}

				ShowErrorMessage(errorMessage, lastResponse ? lastResponse->errorCode : 0);
				// 904 is "user not found in any resolver in this realm" so the user has to be changable -> reset to first step
				if ((lastResponse && lastResponse->errorCode == 904) || _config->otpFailReturnToFirstStep)
				{
					resetToFirstStep = true;
					_config->clearFields = false; // Keep the inputs so the user does not have to repeat them
				}

				ResetMode(resetToFirstStep);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		// PrivacyIDEA completed, move to Password
		else if ((_privacyIDEASuccess || _config->pushAuthenticationSuccess)
			&& (_config->isNextModePassword() || _config->credential.password.empty()))
		{
			PIDebug("PrivacyIDEA completed, moving to PASSWORD mode");
			SetMode(Mode::PASSWORD);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}
		// Username
		else if (_config->credential.username.empty())
		{
			PIDebug("Username still empty, switching to USERNAME mode");
			SetMode(Mode::USERNAME);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}
		// Authentication was successful - log in
		else if (_config->isLastStep())
		{
			PIDebug("Last step completed, logging in...");
			// Reset the authentication
			//_privacyIDEASuccess = false;
			//_config->pushAuthenticationSuccessful = false;
			_config->lastTransactionId = "";
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
			ResetMode(true);
			hr = S_FALSE;
		}
	}

	// Reset things
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
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { PIDebug("CPGSR_NO_CREDENTIAL_FINISHED"); }
		else if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { PIDebug("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		else if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { PIDebug("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		else if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { PIDebug("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { PIDebug("Unknown value for pcpgsr"); }

	PIDebug("CCredential::GetSerialization - END");
	return hr;
}

// If code == 0, the code won't be displayed
void CCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	if (message.empty())
	{
		PIDebug("Cannot show error message without text!");
		return;
	}
	*_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	PIDebug("Error message: " + Convert::ToString(errorMessage));
	SHStrDupW(errorMessage.c_str(), _config->provider.status_text);
}

// If push is successful, reset the credential to do autologin
void CCredential::PushAuthenticationCallback(const PIResponse& response)
{
	PIDebug(__FUNCTION__);
	if (response.isAuthenticationSuccessful())
	{
		_config->pushAuthenticationSuccess = true;
		_config->doAutoLogon = true;
		// When autologon is triggered, connect is called instantly, therefore bypass privacyIDEA on next run
		_config->bypassPrivacyIDEA = true;
		_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
	}
}

bool CCredential::CheckExcludedAccount()
{
	// Check if the user is in the excluded group
	if (!_config->excludedGroup.empty())
	{
		std::vector<std::wstring> groups;

		LPCWSTR serverName = _config->credential.domain.empty() ? nullptr : _config->credential.domain.c_str();
		LPCWSTR userName = _config->credential.username.c_str();

		// Global groups
		DWORD entriesRead = 0, totalEntries = 0;
		GROUP_USERS_INFO_0* pGroupInfo = nullptr;
		NET_API_STATUS nStatus = NetUserGetGroups(
			serverName,
			userName,
			0,
			(LPBYTE*)&pGroupInfo,
			MAX_PREFERRED_LENGTH,
			&entriesRead,
			&totalEntries
		);

		if (nStatus == NERR_Success && pGroupInfo)
		{
			for (DWORD i = 0; i < entriesRead; ++i)
			{
				groups.push_back(pGroupInfo[i].grui0_name);
			}
			NetApiBufferFree(pGroupInfo);
		}
		else
		{
			std::wstringstream ss;
			ss << L"NetUserGetGroups failed for user '" << userName << L"' in domain '"
				<< (serverName ? serverName : L"(local)") << L"' with error: " << nStatus;
			PIError(Convert::ToString(ss.str()));
		}

		// Local groups
		LOCALGROUP_USERS_INFO_0* pLocalGroupInfo = nullptr;
		entriesRead = totalEntries = 0;
		nStatus = NetUserGetLocalGroups(
			serverName,
			userName,
			0,
			LG_INCLUDE_INDIRECT, // 0 would be only direct groups
			(LPBYTE*)&pLocalGroupInfo,
			MAX_PREFERRED_LENGTH,
			&entriesRead,
			&totalEntries
		);

		if (nStatus == NERR_Success && pLocalGroupInfo)
		{
			for (DWORD i = 0; i < entriesRead; ++i)
			{
				groups.push_back(pLocalGroupInfo[i].lgrui0_name);
			}
			NetApiBufferFree(pLocalGroupInfo);
		}
		else
		{
			std::wstringstream ss;
			ss << L"NetUserGetLocalGroups failed for user '" << userName << L"' in domain '"
				<< (serverName ? serverName : L"(local)") << L"' with error: " << nStatus;
			PIError(Convert::ToString(ss.str()));
		}

		// Check if the user is in the excluded group
		for (const auto& group : groups)
		{
			if (Convert::ToUpperCase(group) == Convert::ToUpperCase(_config->excludedGroup))
			{
				PIDebug(L"User is in excluded group: " + _config->excludedGroup);
				return true;
			}
		}
		PIDebug(L"User " + _config->credential.username + L" is not in excluded group: " + _config->excludedGroup);
	}
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
		PIDebug(L"Matching user with excluded account: " + exclAccount);
		if (Convert::ToUpperCase(toCompare) == Convert::ToUpperCase(exclAccount))
		{
			PIDebug("Login data matches excluded account, skipping 2FA...");
			_privacyIDEASuccess = true;
			return true;
		}
	}
	return false;
}

void CCredential::HandleFirstStep()
{

}

HRESULT CCredential::FIDOAuthentication(__in IQueryContinueWithStatus* pqcws)
{
	PIDebug("FIDO2 Authentication " + std::string(_config->useOfflineFIDO ? "offline" : "online") + ", with mode " + _config->ModeString());
	wstring username = _config->credential.username;
	wstring domain = _config->credential.domain;
	// Get the FIDO2SignRequest, either from the last response, passkey challenge, or offline data
	std::optional<FIDOSignRequest> signRequest;
	if (_config->useOfflineFIDO)
	{
		PIDebug("Getting FIDO2SignRequest from offline data");
		signRequest = _privacyIDEA.GetOfflineFIDOSignRequest();
	}
	else if (_config->usePasskey)
	{
		PIDebug("Getting FIDO2SignRequest from passkey challenge");
		signRequest = _passkeyChallenge;
	}
	else
	{
		PIDebug("Getting FIDO2SignRequest from last response");
		signRequest = _config->lastResponse ? _config->lastResponse->GetFIDOSignRequest() : std::nullopt;
	}

	if (!signRequest)
	{
		PIDebug("No FIDO2SignRequest available or no offline data found for user " + Convert::ToString(username));
		SetMode(Mode::PRIVACYIDEA);
		return E_FAIL;
	}

	// DEVICE SEARCH
	// Wait for a device to be connected if necessary. 
	// Afterward, the mode might be reset to get the PIN input or will continue if no PIN is required.
	if (_config->mode == Mode::SEC_KEY_NO_DEVICE)
	{
		auto dev = WaitForFIDODevice(pqcws);
		if (!dev && _fidoDeviceSearchCancelled)
		{
			PIDebug("FIDO2 device search cancelled by user");
			SetMode(Mode::PRIVACYIDEA);
			return E_FAIL;
		}
		const auto mode = SelectFIDOMode();
		if (mode != Mode::SEC_KEY_NO_PIN)
		{
			// Reset to get PIN input
			SetMode(mode);
			_modeSwitched = true;
		}
	}

	// Find the device to use
	auto devices = FIDODevice::GetDevices();
	if (devices.size() == 0)
	{
		PIError("No FIDO2 device available");
		return E_FAIL;
	}

	FIDODevice device = devices.front();
	// Check if a PIN is required and present
	auto pin = Convert::ToString(_config->credential.fido2PIN);
	if (device.HasPin() && pin.empty() && _config->mode == Mode::SEC_KEY_PIN)
	{
		PIDebug("No FIDO2 PIN input, but pin is required");
		return E_FAIL;
	}

	pqcws->SetStatusMessage(_util.GetText(TEXT_TOUCH_SEC_KEY).c_str());
	FIDOSignResponse signResponse;
	string origin = Convert::ToString(Utilities::ComputerName());

	// Offline FIDO2
	if (_config->useOfflineFIDO && _config->mode > Mode::SEC_KEY_ANY)
	{
		PIDebug("Trying offline FIDO2...");
		auto offlineData = _privacyIDEA.offlineHandler.GetAllFIDOData();

		string serialUsed;
		HRESULT res = device.SignAndVerifyAssertion(offlineData, origin, pin, serialUsed);
		if (res != FIDO_OK)
		{
			PIError("FIDO2 offline signing or verifying failed with error: " + to_string(res));
			if (res == FIDO_ERR_TX)
			{
				// Use a more expressive error number
				res = FIDO_DEVICE_ERR_TX;
			}
			_lastStatus = res;
			SetMode(Mode::PRIVACYIDEA);
			return res;
		}
		auto new_username = _privacyIDEA.offlineHandler.GetUsernameForSerial(serialUsed);
		if (!new_username)
		{
			PIError("No username found for serial " + serialUsed);
			_lastStatus = E_FAIL;
			SetMode(Mode::PRIVACYIDEA);
			return E_FAIL;
		}
		username = Convert::ToWString(new_username.value());
		_config->credential.username = username;
		PIDebug(L"FIDO2 offline successful, using username: " + _config->credential.username);
		if (res == FIDO_OK)
		{
			_privacyIDEASuccess = true;
			pqcws->SetStatusMessage(_util.GetText(TEXT_FIDO_CHECKING_OFFLINE_STATUS).c_str());
			_privacyIDEA.OfflineRefillWebAuthn(username, serialUsed);
			_config->useOfflineFIDO = false;
		}
		else
		{
			PIError("FIDO2 offline signing or verifying failed with error: " + to_string(res));
			_lastStatus = res;
		}
	}
	// Passkey (online)
	if (_config->usePasskey && _config->mode > Mode::SEC_KEY_ANY)
	{
		if (!_passkeyChallenge)
		{
			PIError("Unable to get passkey challenge, cannot continue with passkey mode");
			_lastStatus = E_FAIL;
			SetMode(Mode::PRIVACYIDEA);
			return E_FAIL;
		}
		else
		{
			PIDebug("Passkey challenge received: " + _passkeyChallenge.value().ToString());
		}
		HRESULT res = device.Sign(_passkeyChallenge.value(), origin, pin, signResponse);
		if (res != 0)
		{
			PIError("Passkey signing failed with error: " + to_string(res));
			SetMode(Mode::PRIVACYIDEA);
			if (res == FIDO_ERR_TX)
			{
				// Use a more expressive error number
				res = FIDO_DEVICE_ERR_TX;
			}
			_lastStatus = res;
		}

		if (res == FIDO_ERR_NO_CREDENTIALS)
		{
			PIDebug("No credentials available on the device " + device.GetProduct());
			_lastStatus = res;
			return E_FAIL;
		}

		if (res == S_OK)
		{
			PIResponse response;
			res = _privacyIDEA.ValidateCheckWebAuthn(username, domain, signResponse, origin, response,
				_passkeyChallenge.value().transactionId);
			if (SUCCEEDED(res))
			{
				if (response.username)
				{
					PIDebug("Passkey authentication successful, using username " + response.username.value());
					_config->credential.username = Convert::ToWString(response.username.value());
				}
				else
				{
					PIError("Passkey authentication successful, but no username returned in response!");
				}

				_privacyIDEASuccess = response.isAuthenticationSuccessful();
				_config->lastResponse = response;
				_config->usePasskey = false;
			}
		}
	}
	// ONLINE WEBAUTHN
	else if (_config->lastResponse && _config->lastResponse->GetFIDOSignRequest() && !_privacyIDEASuccess)
	{
		PIDebug("Trying online WebAuthn...");
		HRESULT res = device.Sign(_config->lastResponse->GetFIDOSignRequest().value(), origin, pin, signResponse);
		if (res != 0)
		{
			PIError("WebAuthn signing failed with error: " + to_string(res));
			if (res == FIDO_ERR_TX)
			{
				// Use a more expressive error number
				res = FIDO_DEVICE_ERR_TX;
			}
			_lastStatus = res;
		}

		if (res == FIDO_ERR_NO_CREDENTIALS)
		{
			PIDebug("No credentials available on the device " + device.GetProduct());
			_lastStatus = res;
			return E_FAIL;
		}

		if (pqcws->QueryContinue() != S_OK)
		{
			PIError("User cancelled WebAuthn");
			SetMode(Mode::PRIVACYIDEA);
			return E_FAIL;
		}

		if (res == S_OK)
		{
			PIResponse response;
			res = _privacyIDEA.ValidateCheckWebAuthn(username, domain, signResponse, origin, response, _config->lastTransactionId);
			if (SUCCEEDED(res))
			{
				_privacyIDEASuccess = response.value;
				_config->lastResponse = response;
			}
		}
	}
	return S_OK;
}

HRESULT CCredential::FIDORegistration(IQueryContinueWithStatus* pqcws)
{
	PIDebug("FIDO2 registration with mode " + _config->ModeString());
	HRESULT res = S_OK;

	if (!pqcws)
	{
		return E_POINTER;
	}

	if (_config->lastResponse && !_config->lastResponse->passkeyRegistration)
	{
		PIError("No passkey registration available, cannot continue with registration");
		return E_FAIL;
	}

	if (_config->credential.fido2PIN.empty())
	{
		PIDebug("Requesting fido2 PIN for registration");
		SetMode(Mode::SEC_KEY_REG_PIN);
		return E_FAIL;
	}

	auto dev = WaitForFIDODevice(pqcws);
	if (!dev && _fidoDeviceSearchCancelled)
	{
		PIDebug("FIDO2 device search cancelled by user");
		SetMode(Mode::PRIVACYIDEA);
		return E_FAIL;
	}
	else if (!dev)
	{
		PIDebug("No FIDO2 device found, cannot continue with registration");
		SetMode(Mode::PRIVACYIDEA);
		return E_FAIL; // TODO just log in anyway?  
	}

	pqcws->SetStatusMessage(_util.GetText(TEXT_PASSKEY_REGISTER_TOUCH).c_str());
	const auto& request = _config->lastResponse->passkeyRegistration.value();

	std::optional<FIDORegistrationResponse> response = std::nullopt;
	try
	{
		response = dev->Register(_config->lastResponse->passkeyRegistration.value(), Convert::ToString(_config->credential.fido2PIN));
	}
	catch (FIDOException ex)
	{
		PIError("FIDO2 registration failed: " + std::string(ex.what()));
		_lastStatus = ex.getErrorCode();
		if (ex.getErrorCode() == FIDO_ERR_PIN_INVALID)
		{

		}
		else if (ex.getErrorCode() == FIDO_ERR_PIN_AUTH_BLOCKED)
		{
			// We can not provide for all problems, so just show an info in GetSerialization and continue?  
			//_privacyIDEASuccess = true;  
			//return S_OK;  
		}
		else
		{
			SetMode(Mode::PRIVACYIDEA);
			_passkeyRegistrationFailed = true;
		}

		res = E_FAIL;
	}

	if (!response)
	{

	}
	else
	{
		PIResponse piresponse;
		res = _privacyIDEA.ValidateCheckCompletePasskeyRegistration(request.transactionId, request.serial,
			_config->credential.username, _config->credential.domain, response.value(), request.rpId, piresponse);

		if (SUCCEEDED(res) && piresponse.isAuthenticationSuccessful())
		{
			PIDebug("passkey enrollment complete!");
			_privacyIDEASuccess = true;
			_config->lastResponse = piresponse;
			res = S_OK;
		}
		else
		{
			res = E_FAIL;
		}
	}
	return res;
}

std::optional<FIDODevice> CCredential::WaitForFIDODevice(IQueryContinueWithStatus* pqcws, int timeoutMs)
{
	PIDebug("No FIDO2 device found, waiting for device");
	pqcws->SetStatusMessage(_util.GetText(TEXT_FIDO_WAITING_FOR_DEVICE).c_str());

	// In CPUS_CREDUI, pqcws is of no use. Disable UI elements and change the large text to the message 
	// to indicate what the user should do.
	if (_config->provider.cpu == CPUS_CREDUI)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, _util.GetText(TEXT_FIDO_WAITING_FOR_DEVICE).c_str());
		_pCredProvCredentialEvents->SetFieldState(this, FID_LARGE_TEXT, CPFS_DISPLAY_IN_BOTH);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_DISABLED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_DISABLED);
	}

	// Check for changes in HID (USB) and Smartcard (NFC)
	DeviceNotification::Register();
	SmartcardListener sCardListener;
	std::vector<FIDODevice> devices;
	std::optional<FIDODevice> ret = std::nullopt;
	int tries = static_cast<int>(std::ceil(static_cast<double>(timeoutMs) / 200.0));

	while (tries > 0)
	{
		this_thread::sleep_for(chrono::milliseconds(200));
		if (pqcws->QueryContinue() != S_OK)
		{
			PIDebug("User cancelled device search");
			DeviceNotification::Unregister();
			SetMode(Mode::PRIVACYIDEA);
			_fidoDeviceSearchCancelled = true;
			return std::nullopt;
		}
		if (DeviceNotification::newDevices || sCardListener.CheckForSmartcardPresence())
		{
			DeviceNotification::newDevices = false;
			devices = FIDODevice::GetDevices();
			if (devices.size() > 0)
			{
				break;
			}
			else
			{
				PIDebug("Inserted device is not a FIDO2 device");
			}
		}
		tries--;
	}
	if (devices.size() > 0)
	{
		PIDebug("Found " + to_string(devices.size()) + " FIDO2 device(s)");
		ret = devices.front();
		PIDebug("Using device: " + ret->GetProduct());
	}
	else
	{
		PIDebug("No FIDO2 device found");
	}
	if (tries == 0)
	{
		PIDebug("No FIDO2 device found within the timeout period");
	}

	DeviceNotification::Unregister();
	return ret;
}

// Connect is called first after the submit button is pressed.
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{
	PIDebug("CCredential::Connect Mode=" + _config->ModeString());

	_lastStatus = S_OK;
	// Copy the input fields to the config
	_config->provider.field_strings = _rgFieldStrings;
	_util.CopyInputFields();
	wstring username = _config->credential.username;
	wstring domain = _config->credential.domain;
	// Leave the UPN empty if it should not be used
	wstring upn = _config->piconfig.sendUPN ? _config->credential.upn : L"";

	// Default message
	pqcws->SetStatusMessage(_util.GetText(TEXT_CONNECTING).c_str());

	if (_config->mode == Mode::PASSWORD)
	{
		PIDebug("Mode is PASSWORD, skipping Connect");
		return S_OK;
	}

	if (CheckExcludedAccount())
	{
		return S_OK;
	}

	if (_config->bypassPrivacyIDEA)
	{
		PIDebug("Bypassing privacyIDEA...");
		_config->bypassPrivacyIDEA = false;
		return S_OK;
	}

	// Evaluate if and what should be sent to the server depending on the step and configuration
	bool isSendRequest = false, isOfflineCheck = false;
	wstring passToSend;

	// 1st step
	if (_config->mode == Mode::USERNAME || _config->mode == Mode::USERNAMEPASSWORD)
	{
		if (!_config->twoStepSendEmptyPassword && !_config->twoStepSendPassword)
		{
			PIDebug("1st step: Not sending anything");
			// Delay for a short moment, otherwise logonui freezes (???)
			this_thread::sleep_for(chrono::milliseconds(200));
		}
		else
		{
			isSendRequest = true;
			if (!_config->twoStepSendEmptyPassword && _config->twoStepSendPassword)
			{
				passToSend = _config->credential.password;
				PIDebug("1st step: Sending windows pass");
			}
			else
			{
				PIDebug("1st step: Sending empty pass");
			}
		}
	}
	else
	{
		PIDebug("2nd step: Sending OTP/Offline check");
		// Second step or single step authentication, actually use the OTP and do offlineCheck before
		passToSend = _config->credential.otp;
		isOfflineCheck = true;
		isSendRequest = true;
	}

	// Send a request to privacyIDEA, try offline authentication or fido2, depending on what happened before
	if (isSendRequest)
	{
		HRESULT res = E_FAIL;
		// Offline OTP check
		if (isOfflineCheck && (_config->mode < Mode::SEC_KEY_ANY))
		{
			string serialUsed;
			res = _privacyIDEA.OfflineCheck(username, passToSend, serialUsed);
			// Check if a OfflineRefill should be attempted. Either if offlineThreshold is not set, remaining OTPs are below the threshold, or no more OTPs are available.
			if ((res == S_OK && _config->offlineTreshold == 0)
				|| (res == S_OK && _privacyIDEA.offlineHandler.GetOfflineOTPCount(Convert::ToString(username), serialUsed) < _config->offlineTreshold)
				|| res == PI_OFFLINE_DATA_NO_OTPS_LEFT)
			{
				pqcws->SetStatusMessage(_util.GetText(TEXT_OFFLINE_REFILL).c_str());
				const HRESULT refillResult = _privacyIDEA.OfflineRefill(username, passToSend, serialUsed);
				if (refillResult != S_OK)
				{
					PIDebug("OfflineRefill failed " + Convert::LongToHexString(refillResult));
				}
			}

			// Authentication is complete if offlineCheck succeeds, regardless of refill status
			if (res == S_OK)
			{
				_privacyIDEASuccess = true;
			}
		}

		// FIDO2 Authentication
		if (!_privacyIDEASuccess && _config->ModeOneOf(Mode::SEC_KEY_NO_PIN, Mode::SEC_KEY_PIN))
		{
			res = FIDOAuthentication(pqcws);
			if (FAILED(res))
			{
				return res;
			}
		}
		else if (!_privacyIDEASuccess && _config->ModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN))
		{
			if (!_passkeyRegistrationFailed)
			{
				res = FIDORegistration(pqcws);
				if (SUCCEEDED(res))
				{
					_privacyIDEASuccess = true; // Registration is successful
				}
			}
			else
			{
				SetMode(Mode::PRIVACYIDEA);
				res = E_FAIL;
			}
			return res;
		}
		else if (!_privacyIDEASuccess) // OTP
		{
			PIResponse otpResponse;
			// lastTransactionId can be empty
			res = _privacyIDEA.ValidateCheck(username, domain, passToSend, otpResponse, _config->lastTransactionId, upn);

			// Evaluate the response
			if (SUCCEEDED(res))
			{
				// Always show the OTP field, if push was triggered, start polling in background
				if (otpResponse.IsPushAvailable())
				{
					PIDebug("Starting poll with tx id: " + otpResponse.transactionId);
					// When polling finishes, pushAuthenticationCallback is invoked with the finalization success value
					_privacyIDEA.PollTransactionAsync(username, domain, upn, otpResponse.transactionId,
						std::bind(&CCredential::PushAuthenticationCallback, this, std::placeholders::_1));
				}

				// Save the lastTransactionId, so that the lastResponse can be overwritten with an error response and we still have the transactionId
				if (!otpResponse.transactionId.empty())
				{
					_config->lastTransactionId = otpResponse.transactionId;
				}

				if (!otpResponse.challenges.empty())
				{
					PIDebug("Challenges have been triggered");
					// Only one image can be displayed so take the first challenge
					// In the main use-case, token enrollment, there will only be a single challenge
					// because the enrollment is only happening after the authentication is completed
					auto& challenge = otpResponse.challenges.at(0);
					if (!challenge.image.empty())
					{
						// Remove the leading "data:image/png;base64,"
						auto base64image = challenge.image.substr(IMAGE_BASE64_PREFIX.length(), challenge.image.size());
						if (!base64image.empty())
						{
							auto hBitmap = CreateBitmapFromBase64PNG(Convert::ToWString(base64image));
							if (hBitmap != nullptr)
							{
								//_pCredProvCredentialEvents->SetFieldBitmap(this, FID_LOGO, hBitmap);
							}
							else
							{
								PIDebug("Conversion to bitmap failed, image will not be displayed.");
							}
						}
					}
				}
				else
				{
					_privacyIDEASuccess = otpResponse.isAuthenticationSuccessful();
				}

				_config->lastResponse = otpResponse;
			}
			else
			{
				// If an error occured during the first step (send pw/empty) ignore it
				// so the next step, where offline could be done, will still be possible
				if (_config->mode < Mode::PRIVACYIDEA)
				{
					_lastStatus = S_OK;
				}
				else
				{
					_lastStatus = res;
				}
			}
		}
	}

	PIDebug("Authentication complete: " + Convert::ToString(_privacyIDEASuccess));
	PIDebug("Connect - END");
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
	const auto status = bitmap->GetHBITMAP(Gdiplus::Color::White, &hBitmap);
	if (status != Gdiplus::Status::Ok)
	{
		PIError("Getting bitmap failed, gdiplus status: " + to_string(status));
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
	PIDebug(__FUNCTION__);
	PIDebug("ntsStatus: " + Convert::LongToHexString(ntsStatus)
		+ ", ntsSubstatus: " + Convert::LongToHexString(ntsSubstatus));

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	// These status require a complete reset so that there will be no lock out in 2nd step
	if (ntsStatus == STATUS_LOGON_FAILURE || ntsStatus == STATUS_LOGON_TYPE_NOT_GRANTED
		|| (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus != STATUS_PASSWORD_EXPIRED))
	{
		PIDebug("Complete reset!");
		_privacyIDEASuccess = false;
		_config->lastResponse = PIResponse();
		ResetMode(true);
		return S_OK;
	}

	if (_config->credential.passwordMustChange && ntsStatus == 0 && ntsSubstatus == 0)
	{
		// Password change was successful, set this so SetSelected knows to autologon
		_config->credential.passwordMustChange = false;
		_config->credential.passwordChanged = true;
		ResetMode();
		return S_OK;
	}

	bool const pwMustChange = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) || (ntsSubstatus == STATUS_PASSWORD_EXPIRED);
	if (pwMustChange)
	{
		_config->credential.passwordMustChange = true;
		PIDebug("Status: Password must change");
		return S_OK;
	}

	// check if the password update was NOT successfull
	// these two are for new passwords not conform to password policies
	bool pwNotUpdated = (ntsStatus == STATUS_PASSWORD_RESTRICTION) || (ntsSubstatus == STATUS_ILL_FORMED_PASSWORD);
	if (pwNotUpdated)
	{
		PIDebug("Status: Password update failed: Not conform to policies");
	}
	// this catches the wrong old password
	pwNotUpdated = pwNotUpdated || ((ntsStatus == STATUS_LOGON_FAILURE) && (ntsSubstatus == STATUS_INTERNAL_ERROR));

	if (pwNotUpdated)
	{
		// it wasn't updated so we start over again
		_config->credential.passwordMustChange = true;
		_config->credential.passwordChanged = false;
	}

	return S_OK;
}
