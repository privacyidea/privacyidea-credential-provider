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
#include <algorithm>

#include "CCredential.h"
#include "Configuration.h"
#include "RegistryReader.h"
#include "Convert.h"
#include "Logger.h"
#include "FIDODevice.h"
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
	PIDebug("CCredential destructor");
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
	DllRelease();
	if (_config) {
		// This is ugly but safe for now.
		SecureZeroMemory((void*)_config->credential.password.data(),
			_config->credential.password.capacity() * sizeof(wchar_t));
		SecureZeroMemory((void*)_config->credential.otp.data(),
			_config->credential.otp.capacity() * sizeof(wchar_t));
		_config->credential.password.clear();
		_config->credential.otp.clear();
	}
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
	PIDebug(__FUNCTION__);
	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	if (!_config->doAutoLogon)
	{
		SetMode(_config->GetFirstStepMode());
	}

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
// This is also called when the screen is locked during the authentication process because of inactivity.
HRESULT CCredential::UnAdvise()
{
	PIDebug(__FUNCTION__);
	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}

	if (!_config->doAutoLogon)
	{
		FullReset();
	}

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

	if (_config->IsAutoLogonConfigured() && _config->provider.cpu == CPUS_LOGON)
	{
		_config->credential.username = _config->autoLogonUsername;
		_config->credential.domain = _config->autoLogonDomain;
		_config->credential.password = _config->autoLogonPassword;
		_config->doAutoLogon = true;
		PIDebug("AutoLogon is configured");
	}

	if (_config->doAutoLogon)
	{
		// If auto login is enabled, something has happened before, so do not change the mode!
		*pbAutoLogon = TRUE;
		PIDebug("AutoLogon enabled!");
		_config->doAutoLogon = false;
	}
	else
	{
		// This is the initial setup, setting the mode etc.
		if (_config->credential.passwordMustChange
			&& _config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
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
			if (_config->IsFirstStep())
			{
				bool passkeyStarted = false;

				if (_config->passkeyFirstStep && !_config->disablePasskey)
				{
					if (AttemptStartPasskey())
					{
						passkeyStarted = true;
						// Trigger immediate execution (Connect) to start device polling
						*pbAutoLogon = TRUE;
					}
				}

				if (!passkeyStarted)
				{
					// In CPUS_UNLOCK_WORKSTATION the username is already set, so we do not need to set it again.
					// To be able to use two_step_send_(empty_)password, set mode to password then MFA.
					if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
					{
						hr = SetMode(Mode::PASSWORD);
					}
					else
					{
						hr = SetMode(_config->GetFirstStepMode());
					}
				}
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

// Loads a bitmap from a file path, or falls back to a resource if loading fails.
// Returns S_OK and sets *phbmp on success, or an HRESULT error code on failure.
HRESULT CCredential::LoadBitmapFromPathOrResource(const std::wstring& bitmapPath, HBITMAP* phbmp)
{
	if (!phbmp) return E_POINTER;
	*phbmp = nullptr;
	HBITMAP hbmp = nullptr;
	std::string szPath = Convert::ToString(bitmapPath);
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
		*phbmp = hbmp;
		return S_OK;
	}
	else
	{
		const auto hr = HRESULT_FROM_WIN32(GetLastError());
		PIDebug("Failed to load bitmap: " + Convert::LongToHexString(hr));
		return hr;
	}
}

HRESULT CCredential::SetDefaultBitmap()
{
	// Set the original bitmap
	HBITMAP hBitmap = nullptr;
	HRESULT hr = LoadBitmapFromPathOrResource(_config->bitmapPath, &hBitmap);
	if (SUCCEEDED(hr) && hBitmap != nullptr)
	{
		hr = _pCredProvCredentialEvents->SetFieldBitmap(this, FID_LOGO, hBitmap);
		if (FAILED(hr))
		{
			PIDebug("Failed to set bitmap in FullReset: " + Convert::LongToHexString(hr));
		}
	}
	else
	{
		PIDebug("Failed to set bitmap in FullReset: " + Convert::LongToHexString(hr));
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

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		hr = LoadBitmapFromPathOrResource(_config->bitmapPath, phbmp);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	PIDebug(hr);

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
			if (_config->resolveUPN) {
				input = ResolveUpnToNetBios(input);
			}

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
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

bool CCredential::AttemptStartPasskey()
{
	PIDebug("Attempting to start Passkey flow...");
	_config->usePasskey = true;
	PIResponse res;

	const auto hr = _privacyIDEA.ValidateInitialize(res);
	if (FAILED(hr) || !res.passkeyChallenge)
	{
		PIDebug("Failed to initialize Passkey: " + Convert::LongToHexString(hr));
		_config->usePasskey = false;
		return false;
	}

	_passkeyChallenge = res.passkeyChallenge.value();
	std::string uv = _passkeyChallenge.value().userVerification;

	const auto mode = SelectFIDOMode(uv, false);
	SetMode(mode);

	return true;
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
		// WebAuthn / Passkey triggered by PIN, challenge is in last response
		if (_config->lastResponseWithChallenge && _config->lastResponseWithChallenge->GetFIDOSignRequest())
		{
			offline = false;
			uvDiscouraged = _config->lastResponseWithChallenge->GetFIDOSignRequest()->userVerification == "discouraged";
		}
		// Passkey standard, challenge is in _passkeyChallenge
		else if (_passkeyChallenge.has_value())
		{
			offline = false;
			uvDiscouraged = _passkeyChallenge->userVerification == "discouraged";
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

	auto deviceOpt = GetPreferredFIDODevice();

	if (!deviceOpt.has_value())
	{
		PIDebug("No FIDO2 devices found");
		return Mode::SEC_KEY_NO_DEVICE;
	}

	FIDODevice device = deviceOpt.value();
	PIDebug("SelectFIDOMode using device: " + device.GetProduct());

	// Check capabilities
	if (device.IsWinHello())
	{
		return Mode::SEC_KEY_NO_PIN;
	}

	if (_config->isRemoteSession)
	{
		PIDebug("Not requesting PIN because it is a remote session");
		return Mode::SEC_KEY_NO_PIN;
	}
	else if (device.HasPin() && ((!uvDiscouraged && !offline) || (!_config->webAuthnOfflineNoPIN && offline)))
	{
		return Mode::SEC_KEY_PIN;
	}

	return Mode::SEC_KEY_NO_PIN;
}

HRESULT CCredential::SetMode(Mode mode)
{
	PIDebug("SetMode: New Mode=" + _config->ModeToString(mode) + ", old Mode=" + _config->ModeString() +
		", passkey = " + to_string(_config->usePasskey) + ", offlineFIDO = " + to_string(_config->useOfflineFIDO));

	if (_pCredProvCredentialEvents == nullptr)
	{
		PIError("SetMode called without CredentialEvents available!");
		return E_FAIL;
	}

	if (mode != Mode::NO_CHANGE)
	{
		_config->mode = mode;
	}

	const Mode oldMode = _config->mode; // Keep old mode for "Hide First Step Error" logic
	HRESULT hr = S_OK;
	std::wstring smallText;

	// Configure Fields & Submit Button based on Mode
	const FIELD_STATE_PAIR* pFieldStates = nullptr;
	DWORD submitButtonField = FID_PASSWORD;
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pinState = CPFIS_FOCUSED;

	switch (mode)
	{
	case Mode::USERNAME:
		pFieldStates = &s_rgScenarioUsername[0];
		submitButtonField = FID_USERNAME;
		smallText = _util.GetText(TEXT_ENTER_USERNAME);
		break;

	case Mode::PASSWORD:
		pFieldStates = &s_rgScenarioPassword[0];
		submitButtonField = FID_PASSWORD;
		smallText = _util.GetText(TEXT_ENTER_PASSWORD);
		break;

	case Mode::USERNAMEPASSWORD:
		pFieldStates = &s_rgScenarioUsernamePassword[0];
		submitButtonField = FID_PASSWORD;
		smallText = _util.GetText(TEXT_ENTER_USERNAME_PASSWORD);
		break;

	case Mode::PRIVACYIDEA:
		pFieldStates = &s_rgScenarioPrivacyIDEA[0];
		submitButtonField = FID_OTP;

		// Force OTP field visibility
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_ONLINE_FIDO).c_str());

		// Determine small text based on errors/response
		smallText = _util.GetText(TEXT_OTP_PROMPT);
		if (_config->lastResponse.has_value())
		{
			const bool hideFirstStepError = _config->hideFirstStepResponseError && IsModeOneOf(oldMode, Mode::USERNAME, Mode::USERNAMEPASSWORD);
			const bool isRejected = _config->lastResponse->authenticationStatus == AuthenticationStatus::REJECT;
			std::string serverMsg = _config->lastResponse->GetNonFIDOMessage();

			if (!hideFirstStepError && !serverMsg.empty() && !_config->lastResponse->isAuthenticationSuccessful())
			{
				smallText = Convert::ToWString(serverMsg);
			}
		}
		break;

	case Mode::CHANGE_PASSWORD:
		pFieldStates = &s_rgScenarioPasswordChange[0];
		submitButtonField = FID_NEW_PASS_2;
		// Pre-fill user/pass for change flow
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, _config->credential.username.c_str());
		_pCredProvCredentialEvents->SetFieldString(this, FID_PASSWORD, _config->credential.password.c_str());
		break;

	case Mode::SEC_KEY_SET_PIN:
		pFieldStates = &s_rgScenarioSetPin[0];
		submitButtonField = FID_NEW_PASS_2;
		smallText = _util.GetText(TEXT_SET_NEW_SEC_KEY_PIN);
		break;

	case Mode::SEC_KEY_SELECT_USER:
		pFieldStates = &s_rgScenarioSelectUser[0];
		submitButtonField = FID_USER_SELECT;
		smallText = L"Select the user for this security key.";
		// Ensure the ComboBox is focused
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_USER_SELECT, CPFIS_FOCUSED);
		break;

	case Mode::SEC_KEY_REG_PIN:
	case Mode::SEC_KEY_REG:
	case Mode::SEC_KEY_PIN:
	case Mode::SEC_KEY_NO_DEVICE:
	case Mode::SEC_KEY_NO_PIN:
		pFieldStates = &s_rgScenarioSecurityKey[0];
		submitButtonField = FID_FIDO_PIN;

		// PIN Field State logic
		if (mode == Mode::SEC_KEY_NO_PIN) pinState = CPFIS_NONE;
		else pinState = CPFIS_FOCUSED;

		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_FIDO_PIN, pinState);

		// Link Text logic
		if (_config->usePasskey)
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_LOGIN_WITH_USERNAME).c_str());
		else
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_OTP).c_str());

		// Text Logic
		if (mode == Mode::SEC_KEY_REG_PIN)
		{
			if (_lastStatus == FIDO_ERR_PIN_INVALID) smallText = _util.GetText(TEXT_FIDO_ERR_PIN_INVALID);
			else smallText = _util.GetText(TEXT_PASSKEY_REGISTRATION) + L". " + _util.GetText(TEXT_SEC_KEY_ENTER_PIN_PROMPT);
		}
		else if (mode == Mode::SEC_KEY_PIN)
		{
			smallText = _util.GetText(TEXT_SEC_KEY_ENTER_PIN_PROMPT);
		}
		break;

	case Mode::NO_CHANGE:
		return S_OK;

	default:
		PIError("SetMode: Unknown mode");
		return E_FAIL;
	}

	// Batch Apply Field States & Submit Button
	if (pFieldStates) hr = _util.SetFieldStatePairBatch(this, _pCredProvCredentialEvents, pFieldStates);
	_pCredProvCredentialEvents->SetFieldSubmitButton(this, FID_SUBMIT_BUTTON, submitButtonField);

	// Set Focus Logic
	if (mode == Mode::SEC_KEY_SET_PIN)
	{
		// Force Old Password and OTP to hidden (overriding the scenario default)
		_pCredProvCredentialEvents->SetFieldState(this, FID_PASSWORD, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
		// Force focus to the New PIN field so the user can type immediately
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_NEW_PASS_1, CPFIS_FOCUSED);
	}
	if (mode == Mode::SEC_KEY_PIN)
	{
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_FIDO_PIN, CPFIS_FOCUSED);
	}

	// Configure Common Text Elements

	// Offline Link Text
	_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_OFFLINE, _util.GetText(TEXT_USE_OFFLINE_FIDO).c_str());

	// Large Text (Username or Login Text)
	std::wstring largeText;
	if (!_config->hideFullName)
	{
		if (!_config->credential.username.empty())
		{
			largeText = _config->credential.username;
			if (!_config->credential.domain.empty() && !_config->hideDomainName)
			{
				largeText.append(L"@").append(_config->credential.domain);
			}
		}
	}
	if (largeText.empty()) largeText = _util.GetText(TEXT_LOGIN_TEXT); // Default

	_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, largeText.c_str());
	_pCredProvCredentialEvents->SetFieldState(this, FID_LARGE_TEXT, largeText.empty() ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE);

	// Small Text (Prompt)
	_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, smallText.c_str());
	_pCredProvCredentialEvents->SetFieldState(this, FID_SMALL_TEXT, smallText.empty() ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE);

	// Subtext (Domain Hint)
	if (_config->showDomainHint && !_config->credential.domain.empty())
	{
		std::wstring domainText = _util.GetText(TEXT_DOMAIN_HINT) + _config->credential.domain;
		_pCredProvCredentialEvents->SetFieldString(this, FID_SUBTEXT, domainText.c_str());
	}
	else
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_SUBTEXT, CPFS_HIDDEN);
	}

	if (mode == Mode::SEC_KEY_SET_PIN)
	{
		// Now it is safe to hide them. The scenario has already been applied.
		_pCredProvCredentialEvents->SetFieldState(this, FID_PASSWORD, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);

		// Focus to the New PIN field
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_NEW_PASS_1, CPFIS_FOCUSED);
	}

	// Focus Password field if Username is already present
	PWSTR currentUsername = nullptr;
	this->GetStringValue(FID_USERNAME, &currentUsername);
	if (currentUsername && currentUsername[0] != 0)
	{
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_FOCUSED);
	}
	CoTaskMemFree(currentUsername);


	// Configure Command Links (Visibility & Text)

	// Determine Link Visibility Flags
	bool showFidoOnline = (mode > Mode::SEC_KEY_ANY);
	bool showFidoOffline = false;
	bool showReset = (_config->showResetLink && !_config->IsFirstStep());

	// FIDO Online Link: Passkey offered in first step or WebAuthn/Passkey challenge-response
	if (_config->IsFirstStep() && !_config->disablePasskey)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_ONLINE, _util.GetText(TEXT_USE_PASSKEY).c_str());
		showFidoOnline = true;
	}
	else if (_config->lastResponseWithChallenge && _config->lastResponseWithChallenge->GetFIDOSignRequest())
	{
		showFidoOnline = true;
	}

	// FIDO Offline Link
	if (_config->webAuthnOfflineSecondStep || _config->IsFirstStep())
	{
		// Check if explicitly hidden in config
		const bool hiddenInFirstStep = (_config->IsModeOneOf(Mode::USERNAME, Mode::USERNAMEPASSWORD, Mode::PASSWORD) && _config->webAuthnOfflineHideFirstStep);

		if (!hiddenInFirstStep)
		{
			// Show if ANY data exists on the machine (generic, for usernameless auth) 
			// or if the specifically typed user has data (when username+password has already been entered, so second step here)
			if (_config->IsFirstStep())
			{
				if (!_privacyIDEA.offlineHandler.GetAllFIDOData().empty())
				{
					showFidoOffline = true;
				}
			}
			else
			{
				if (_privacyIDEA.OfflineFIDODataExistsFor(_config->credential.username))
				{
					showFidoOffline = true;
				}
			}
		}
	}

	// Special Case: Offline link in Second Step to make it look the same as online authentication ("seamless").
	// Only show if the setting is enabled AND the current user actually has offline data.
	if ((mode == Mode::PRIVACYIDEA || mode > Mode::SEC_KEY_ANY)
		&& _config->webAuthnOfflineSecondStep
		&& !showFidoOnline)
	{
		// Check if THIS user has data.
		if (_privacyIDEA.OfflineFIDODataExistsFor(_config->credential.username))
		{
			_pCredProvCredentialEvents->SetFieldString(this, FID_FIDO_OFFLINE, _util.GetText(TEXT_USE_ONLINE_FIDO).c_str());
			showFidoOffline = true;
		}
	}

	// Special Case: Hide Reset Link in Passkey mode
	if (_config->usePasskey && _config->mode > Mode::SEC_KEY_ANY) showReset = false;
	if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && mode == Mode::PASSWORD) showReset = false;

	// Overrides: Hide EVERYTHING during Enrollment or Change Password or User selection
	if (_config->IsModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN, Mode::CHANGE_PASSWORD, Mode::SEC_KEY_SET_PIN, Mode::SEC_KEY_SELECT_USER))
	{
		showFidoOnline = false;
		showFidoOffline = false;
		showReset = false;
		_pCredProvCredentialEvents->SetFieldState(this, FID_OFFLINE_INFO, CPFS_HIDDEN);
	}

	// Apply states to links (FIDO Online, FIDO Offline, Reset)
	_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_ONLINE, showFidoOnline ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
	_pCredProvCredentialEvents->SetFieldState(this, FID_FIDO_OFFLINE, showFidoOffline ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
	_pCredProvCredentialEvents->SetFieldState(this, FID_RESET_LINK, showReset ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);

	// Update Offline Info
	if (_config->offlineShowInfo)
	{
		PWSTR pwszUser = nullptr;
		this->GetStringValue(FID_USERNAME, &pwszUser);
		if (pwszUser) SetOfflineInfo(Convert::ToString(std::wstring(pwszUser)));
		CoTaskMemFree(pwszUser);
	}

	// Cancel Enrollment Link
	const bool versionHigherThan312 = _config->lastResponseWithChallenge && _config->lastResponseWithChallenge->IsVersionHigherOrEqual(3, 12);
	if ((_enrollmentInProgress || _pollEnrollmentInProgress) && versionHigherThan312 && _config->lastResponseWithChallenge->isEnrollCancellable)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_CANCEL_ENROLLMENT, _util.GetText(TEXT_CANCEL_ENROLLMENT).c_str());
		_pCredProvCredentialEvents->SetFieldState(this, FID_CANCEL_ENROLLMENT, CPFS_DISPLAY_IN_SELECTED_TILE);
	}

	// Unlock Workstation specific hiding of username input, username is already known
	if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
	{
		_pCredProvCredentialEvents->SetFieldState(this, FID_USERNAME, CPFS_HIDDEN);
	}

	return hr;
}

HRESULT CCredential::FullReset()
{
	PIDebug(__FUNCTION__);
	HRESULT hr = S_OK;
	// Reset the credential to the initial state, clearing all fields and resetting the mode.
	StopPoll();
	_config->lastResponse = {};
	_config->lastTransactionId = "";
	_config->pushAuthenticationSuccess = false;
	_privacyIDEASuccess = false;
	_lastStatus = S_OK;
	_enrollmentInProgress = false;
	_pollEnrollmentInProgress = false;

	// Do not reset the username/domain in CPUS_UNLOCK_WORKSTATION, because it is "locked in".
	if (_config->provider.cpu != CPUS_UNLOCK_WORKSTATION)
	{
		_config->credential.username = L"";
		_config->credential.domain = _initialDomain;
	}
	_config->credential.password = L"";
	if (_pCredProvCredentialEvents != nullptr)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);

		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
		{
			// In case of unlock, set the mode to password, because the username is already set.
			hr = SetMode(Mode::PASSWORD);
		}
		else if (_config->IsPasswordInFirstStep())
		{
			hr = SetMode(Mode::USERNAMEPASSWORD);
		}
		else
		{
			hr = SetMode(Mode::USERNAME);
		}
		SetDefaultBitmap();
	}
	return hr;
}

/// <summary>
/// Resets the credential provider's mode, optionally to the first step, and clears relevant fields as needed. If resetToFirstStep is true,
/// the last response and transaction ID are cleared, and the mode is set to the first step.
/// </summary>
/// <param name="resetToFirstStep">If true, resets the mode to the first step regardless of the current mode; otherwise, restores the previous or default mode.</param>
/// <returns>Returns S_OK on success, or an HRESULT error code on failure.</returns>
/// TODO this function is probably obsolete
HRESULT CCredential::ResetMode(bool resetToFirstStep)
{
	PIDebug("CCredential::ResetMode with resetToFirstStep=" + to_string(resetToFirstStep));
	_privacyIDEA.StopPoll();
	// If resetToFirstStep is true, the mode is reset to the first step regardless of the current mode.
	if (resetToFirstStep)
	{
		FullReset();
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

	if (dwFieldID == FID_USER_SELECT)
	{
		*pcItems = static_cast<DWORD>(_currentSignResponse.assertions.size());
		*pdwSelectedItem = _selectedAssertionIndex;
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
	if (dwFieldID == FID_USER_SELECT && dwItem < _currentSignResponse.assertions.size())
	{
		std::string label = _currentSignResponse.assertions[dwItem].displayName;
		if (label.empty()) label = _currentSignResponse.assertions[dwItem].username;
		if (label.empty()) label = "Unknown User";

		return SHStrDupW(Convert::ToWString(label).c_str(), ppwszItem);
	}
	return E_INVALIDARG;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
	PIDebug("SetComboBoxSelectedValue, selected item: " + to_string(dwSelectedItem));
	if (dwFieldID == FID_USER_SELECT)
	{
		_selectedAssertionIndex = dwSelectedItem;
		return S_OK;
	}
	return E_INVALIDARG;
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
		if (_config->IsFirstStep() && !_config->useOfflineFIDO)
		{
			PIDebug("CommandLinkClicked: Passkey Online");
			if (!AttemptStartPasskey())
			{
				return S_OK; // Failed, do nothing (error already logged)
			}
			// Trigger immediate execution via reenumeration -> autologon -> connect()
			if (_config->IsModeOneOf(Mode::SEC_KEY_NO_DEVICE, Mode::SEC_KEY_NO_PIN))
			{
				_config->doAutoLogon = true;
				_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
			}
			return S_OK;
		}
		// FIDO Offline
		else if (_config->IsFirstStep() && _config->useOfflineFIDO)
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
	else if (dwFieldID == FID_CANCEL_ENROLLMENT)
	{
		PIDebug("Cancel enrollment link clicked");
		if (!_config->lastTransactionId.empty())
		{
			if (_privacyIDEA.CancelEnrollmentViaMultichallenge(_config->lastTransactionId))
			{
				_enrollmentInProgress = false;
				_pollEnrollmentInProgress = false;
				_privacyIDEASuccess = true;
				_config->doAutoLogon = true;
				_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
			}
		}
	}
	else
	{
		PIDebug("Unknown command link clicked: " + to_string(dwFieldID));
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

	// Staying in SET_PIN mode until successful
	if (_config->mode == Mode::SEC_KEY_SET_PIN && !_privacyIDEASuccess)
	{
		// Display error if one occurred during connect
		if (_lastStatus == FIDO_PINS_DO_NOT_MATCH)
		{
			ShowErrorMessage(L"PINs do not match or are empty.");
			// Reset status so the error doesn't persist if we refresh for other reasons
			_lastStatus = S_OK;
			_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
		}

		// Stay in this mode and return
		PIDebug("Maintaining SEC_KEY_SET_PIN mode waiting for input.");
		*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		return S_OK;
	}

	// Staying in USER_SELECT mode until successful
	if (_config->mode == Mode::SEC_KEY_SELECT_USER && !_privacyIDEASuccess)
	{
		PIDebug("Maintaining SEC_KEY_SELECT_USER mode waiting for selection.");
		*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		// Prevent fields from being cleared so the UI stays stable
		_config->clearFields = false;
		return S_OK;
	}

	// Password change evaluation
	if (_config->credential.passwordMustChange)
	{
		if (_config->credential.newPassword1 == _config->credential.newPassword2)
		{
			// Determine the correct "Domain" to send to the LSA.
			// 1. If it's a real Domain User, use the domain name.
			// 2. If it's a Local User (WORKGROUP, ".", or ComputerName), we MUST use the ComputerName.
			//    Passing "WORKGROUP" causes error 0xc0020008 (Network address invalid).
			std::wstring targetDomain = _config->credential.domain;
			std::wstring computerName = _util.ComputerName();

			const bool isLocal = (targetDomain == computerName ||
				targetDomain == L"WORKGROUP" ||
				targetDomain == L".");

			if (isLocal)
			{
				PIDebug("Local account detected. Forcing domain to ComputerName for password change.");
				targetDomain = computerName;
			}

			hr = _util.KerberosChangePassword(pcpgsr, pcpcs,
				_config->credential.username,
				_config->credential.password,
				_config->credential.newPassword1,
				targetDomain);
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
			// Continue with fido in the following cases:
			// privacyIDEA says so with the preferred_client_mode, or the local setting is set and there is a sign request,
			// or when continuing fido (e.g. from NO_DEVICE to PIN)
			bool continueWithFIDO = false;
			if (lastResponse)
			{
				continueWithFIDO = lastResponse->preferredMode == "webauthn"
					|| (_config->webAuthnPreferred && (lastResponse->GetFIDOSignRequest()))
					|| (_config->mode > Mode::SEC_KEY_ANY);
			}

			bool hasOnlineRequest = lastResponse && lastResponse->GetFIDOSignRequest().has_value();

			// Alternatively, if webAuthnOfflineSecondStep is enabled, the user has offline FIDO data and the offlinePreferFIDO is set,
			// continue with a FIDO mode aswell.
			if (_config->webAuthnOfflinePreferred && _config->webAuthnOfflineSecondStep
				&& _privacyIDEA.OfflineFIDODataExistsFor(_config->credential.username)
				&& !hasOnlineRequest)
			{
				continueWithFIDO = true;
				_config->useOfflineFIDO = true; // Simulate the link click
			}

			PIDebug("Continue with FIDO: " + to_string(continueWithFIDO));
			// If the user cancelled the operation, do not continue with FIDO
			if (_fidoDeviceSearchCancelled || _lastStatus == FIDO_ERR_OPERATION_DENIED)
			{
				continueWithFIDO = false;
				_fidoDeviceSearchCancelled = false;
			}
			// Passkey Registration
			if (lastResponse && lastResponse->passkeyRegistration && _lastStatus == S_OK)
			{
				// Go to Connect directly for the first time
				if (!_passkeyRegistrationFailed && !_config->IsModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN, Mode::SEC_KEY_SET_PIN))
				{
					SetMode(Mode::SEC_KEY_REG);
					_config->doAutoLogon = true;
					_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
				else if (_config->IsModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN, Mode::SEC_KEY_SET_PIN))
				{
					// continue in this mode
					PIDebug("Continuing in mode: " + _config->ModeString());
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}
			}
			// Regular second step, asking for second factor. Can also be that the mode was switched (FIDO <-> OTP)
			else if (_config->IsModeOneOf(Mode::USERNAME, Mode::USERNAMEPASSWORD, Mode::PASSWORD)
				&& (_lastStatus == S_OK || _modeSwitched))
			{
				PIDebug("Moving to privacyIDEA step");
				_modeSwitched = false;
				_config->clearFields = false;
				SetMode(continueWithFIDO ? SelectFIDOMode() : Mode::PRIVACYIDEA);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				// For Mode::SEC_KEY_NO_DEVICE, Mode::SEC_KEY_NO_PIN or RDP (windows hello, also no PIN) we need to get to connect
				// instantly to trigger the security key or windows hello on the source machine in case of RDP.
				if (continueWithFIDO && (_config->IsModeOneOf(Mode::SEC_KEY_NO_DEVICE, Mode::SEC_KEY_NO_PIN) || _config->isRemoteSession))
				{
					_config->doAutoLogon = true;
					_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
				}
			}
			// Another challenge was triggered: repeat the privacyidea step
			else if (lastResponse && !lastResponse->challenges.empty() && _lastStatus == S_OK)
			{
				PIDebug("Another challenge was triggered, repeating privacyIDEA step");
				SetMode(continueWithFIDO ? SelectFIDOMode() : Mode::PRIVACYIDEA);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				if (continueWithFIDO && (_config->IsModeOneOf(Mode::SEC_KEY_NO_DEVICE, Mode::SEC_KEY_NO_PIN) || _config->isRemoteSession))
				{
					_config->doAutoLogon = true;
					_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
				}
			}
			// Show an error message if authentication failed or there is an error
			else if (_lastStatus != S_OK || (lastResponse && lastResponse->challenges.empty() && !lastResponse->value &&
				_config->mode >= Mode::PRIVACYIDEA))
			{
				bool resetToFirstStep = false;
				wstring errorMessage;

				// 1. PRIORITY: Specific Local FIDO Errors
				switch (_lastStatus)
				{
				case FIDO_ERR_OPERATION_DENIED:
					errorMessage = _util.GetText(TEXT_FIDO_CANCELLED);
					if (_config->credential.username.empty())
					{
						resetToFirstStep = true;
					}
					else
					{
						SetMode(Mode::PRIVACYIDEA);
					}
					break;

				case FIDO_ERR_NO_CREDENTIALS:
					errorMessage = _util.GetText(TEXT_FIDO_ERR_NO_CREDENTIALS);
					SetMode(Mode::PRIVACYIDEA);
					break;

				case FIDO_ERR_PIN_AUTH_BLOCKED:
					errorMessage = _util.GetText(TEXT_FIDO_ERR_PIN_BLOCKED);
					// If UV is discouraged, we must reset to avoid infinite loop
					if (lastResponse && lastResponse->GetFIDOSignRequest()
						&& lastResponse->GetFIDOSignRequest()->userVerification == "discouraged")
					{
						resetToFirstStep = true;
					}
					break;

				case FIDO_DEVICE_ERR_TX:
					errorMessage = _util.GetText(TEXT_FIDO_ERR_TX);
					resetToFirstStep = true;
					break;

				case FIDO_ERR_PIN_INVALID:
					errorMessage = _util.GetText(TEXT_FIDO_ERR_PIN_INVALID);
					break;
				default:
					break; // to go priority 2
				}

				// Server messages (Only if no local error message set)
				if (errorMessage.empty())
				{
					if (lastResponse && !lastResponse->errorMessage.empty())
					{
						errorMessage = Convert::ToWString(lastResponse->errorMessage);
					}
					else if (lastResponse && !lastResponse->message.empty())
					{
						errorMessage = Convert::ToWString(lastResponse->message);
					}
					// Fallback to generic messages
					else
					{
						if (_lastStatus != S_OK)
						{
							errorMessage = _util.GetText(TEXT_GENERIC_ERROR);
						}
						else
						{
							errorMessage = _util.GetText(TEXT_WRONG_OTP);
						}
					}
				}

				ShowErrorMessage(errorMessage, lastResponse ? lastResponse->errorCode : 0);

				// 904 is "user not found in any resolver in this realm" -> reset to first step
				if ((lastResponse && lastResponse->errorCode == 904) || _config->otpFailReturnToFirstStep)
				{
					resetToFirstStep = true;
					_config->clearFields = false; // Keep inputs
				}

				ResetMode(resetToFirstStep);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			// If we are in a PIN entry mode (Standard or Registration), stay there and wait for input.
			else if (_config->IsModeOneOf(Mode::SEC_KEY_PIN, Mode::SEC_KEY_REG_PIN))
			{
				PIDebug("Maintaining FIDO PIN mode waiting for input.");
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				_config->clearFields = false;
			}
			else
			{
				// Just move to privacyIDEA step
				PIDebug("privacyIDEA not completed yet, moving to privacyIDEA step");
				SetMode(Mode::PRIVACYIDEA);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		// PrivacyIDEA completed, move to Password
		else if ((_privacyIDEASuccess || _config->pushAuthenticationSuccess) && _config->credential.password.empty())
		{
			PIDebug("privacyIDEA step completed, moving to Password step");
			if (_enrollmentInProgress || _pollEnrollmentInProgress)
			{
				_enrollmentInProgress = false;
				_pollEnrollmentInProgress = false;
				SetDefaultBitmap();
			}
			SetMode(Mode::PASSWORD);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}
		// Username
		else if (_config->credential.username.empty())
		{
			PIDebug("Username still empty, moving to Username step");
			SetMode(Mode::USERNAME);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}
		// Authentication was successful - log in
		else if (_config->IsCredentialComplete() && (_privacyIDEASuccess || _config->pushAuthenticationSuccess))
		{

			PIDebug("Last step completed, logging in...");
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
			PIDebug("GetSerialization: No case matches state.");
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
	_pollEnrollmentInProgress = false;
}

bool CCredential::CheckExcludedAccount()
{
	PIDebug("CCredential::CheckExcludedAccount");
	// Check if the user is in the excluded group
	if (!_config->excludedGroup.empty())
	{
		std::vector<std::wstring> groups;

		wstring tmp = wstring(_config->credential.domain + L"\\" + _config->credential.username);
		LPCWSTR userAndDomain = tmp.c_str();
		LPCWSTR userOnly = _config->credential.username.c_str();
		// Global groups
		DWORD entriesRead = 0, totalEntries = 0;
		GROUP_USERS_INFO_0* pGroupInfo = nullptr;
		NET_API_STATUS nStatus = NERR_Success;
		// It is only possible to check global groups if the netbios address of the machine that should be queried is set
		if (!_config->exludedGroupNetBIOSaddress.empty())
		{
			nStatus = NetUserGetGroups(
				_config->exludedGroupNetBIOSaddress.c_str(),
				userOnly,
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
				ss << L"NetUserGetGroups failed for user '" << userAndDomain << L"' with error: " << nStatus;
				PIError(Convert::ToString(ss.str()));
			}
		}
		else
		{
			PIDebug("Unable to check global groups, no netbios address set for excluded group");
		}

		// Local groups
		LOCALGROUP_USERS_INFO_0* pLocalGroupInfo = nullptr;
		entriesRead = totalEntries = 0;
		nStatus = NetUserGetLocalGroups(
			NULL,
			userAndDomain,
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
			ss << L"NetUserGetLocalGroups failed for user '" << userAndDomain << L"' with error: " << nStatus;
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
		if (Convert::ToUpperCase(toCompare) == Convert::ToUpperCase(exclAccount))
		{
			PIDebug("Login data matches excluded account");
			_privacyIDEASuccess = true;
			return true;
		}
	}
	return false;
}

bool CCredential::IsRpIdAllowed(const std::string& rpId)
{
	// TODO no RP ID configuration is currently accepted.
	if (_config->trustedRPIDs.empty())
	{
		return true;
	}

	for (const auto& allowed : _config->trustedRPIDs)
	{
		std::string sAllowed = Convert::ToString(allowed);

		// Case-insensitive comparison!
		if (_stricmp(rpId.c_str(), sAllowed.c_str()) == 0)
		{
			return true;
		}
	}

	PIError("SECURITY ALERT: FIDO Operation blocked! Request contained RPID '" + rpId +
		"' which is not in the configured allow list (trusted_rpids)!");

	return false;
}

std::optional<FIDODevice> CCredential::GetPreferredFIDODevice()
{
	// Check if Windows Hello should be used:
	// We are in CredUI (UAC) mode AND the admin has not disabled the use of native Windows Hello
	// We are in a Remote Session (RDP **must** use Hello platform to tunnel)
	const bool prioritizeHello = (_config->provider.cpu == CPUS_CREDUI && _config->useWindowsHelloForCredUI) || _config->isRemoteSession;
	if (prioritizeHello)
	{
		auto wh = FIDODevice::GetWinHello();
		if (wh.has_value())
		{
			PIDebug("GetPreferredFIDODevice: Found Windows Hello (Priority target)");
			return wh;
		}
		PIDebug("GetPreferredFIDODevice: Windows Hello requested but not found. Falling back to standard search...");
	}
	// Standard Device Search
	// If we are local, filter out Windows Hello (since we would have returned it above if we wanted it).
	// If we are remote but Hello failed above, we check everything just in case.
	const bool filterWindowsHello = !_config->isRemoteSession;

	// Pass 'false' for logging to avoid spamming the log file during polling loops
	auto devices = FIDODevice::GetDevices(filterWindowsHello, false);

	if (!devices.empty())
	{
		// Just return the first valid device found
		return devices[0];
	}

	return std::nullopt;
}

HRESULT CCredential::FIDOAuthentication(IQueryContinueWithStatus* pqcws)
{
	PIDebug("FIDO2 Authentication " + std::string(_config->useOfflineFIDO ? "offline" : "online") + ", with mode " + _config->ModeString());
	wstring username = _config->credential.username;
	wstring domain = _config->credential.domain;

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
		signRequest = _config->lastResponseWithChallenge ? _config->lastResponseWithChallenge->GetFIDOSignRequest() : std::nullopt;
	}

	if (!signRequest)
	{
		PIDebug("No FIDO2SignRequest available or no offline data found for user " + Convert::ToString(username));
		SetMode(Mode::PRIVACYIDEA);
		return E_FAIL;
	}

	// RP ID check
	if (!IsRpIdAllowed(signRequest->rpId))
	{
		SetMode(Mode::PRIVACYIDEA);
		return E_FAIL;
	}

	// Device search
	if (_config->mode == Mode::SEC_KEY_NO_DEVICE)
	{
		auto dev = WaitForFIDODevice(pqcws);
		if (!dev && _fidoDeviceSearchCancelled)
		{
			PIDebug("FIDO2 device search cancelled by user");
			_lastStatus = FIDO_ERR_OPERATION_DENIED;
			_config->usePasskey = false;
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

	auto deviceOpt = GetPreferredFIDODevice();

	if (!deviceOpt.has_value())
	{
		PIError("No FIDO2 device available during authentication step.");
		return E_FAIL;
	}

	FIDODevice device = deviceOpt.value();
	PIDebug("FIDOAuthentication: Using device: " + device.GetPath());

	// Check if a PIN is required and present
	auto pin = Convert::ToString(_config->credential.fido2PIN);
	if (device.HasPin() && pin.empty() && _config->mode == Mode::SEC_KEY_PIN)
	{
		PIDebug("No FIDO2 PIN input, but pin is required");
		return E_FAIL;
	}

	std::wstring text;
	if (device.IsWinHello())
	{
		text = _util.GetText(TEXT_GUIDE_USE_WINDOWS_HELLO);
	}
	else
	{
		text = _util.GetText(TEXT_TOUCH_SEC_KEY);
	}

	if (_config->provider.cpu == CPUS_CREDUI)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, text.c_str());
		_pCredProvCredentialEvents->SetFieldState(this, FID_LARGE_TEXT, CPFS_DISPLAY_IN_BOTH);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_DISABLED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_DISABLED);
	}
	else
	{
		pqcws->SetStatusMessage(text.c_str());
	}

	FIDOSignResponse signResponse;
	string origin = Convert::ToString(Utilities::ComputerName());

	// Offline FIDO
	if (_config->useOfflineFIDO && _config->mode > Mode::SEC_KEY_ANY)
	{
		PIDebug("Trying offline FIDO2...");
		auto offlineData = _privacyIDEA.offlineHandler.GetAllFIDOData();

		string serialUsed;
		HRESULT hr = device.SignAndVerifyAssertion(offlineData, origin, pin, serialUsed);

		if (hr != FIDO_OK)
		{
			PIDebug("Offline FIDO failed (Error " + to_string(hr) + "). Checking for Online fallback...");
			const bool hasOnlineChallenge = (_config->lastResponseWithChallenge && _config->lastResponseWithChallenge->GetFIDOSignRequest())
				|| _passkeyChallenge.has_value();

			if (hasOnlineChallenge)
			{
				PIDebug("Online challenge exists. Switching to Online Mode.");
				_config->useOfflineFIDO = false;
			}
			else
			{
				if (hr == FIDO_ERR_TX) hr = FIDO_DEVICE_ERR_TX;
				_lastStatus = hr;
				SetMode(Mode::PRIVACYIDEA);
				return hr;
			}
		}
		else // Success
		{
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
			_privacyIDEASuccess = true;
			pqcws->SetStatusMessage(_util.GetText(TEXT_FIDO_CHECKING_OFFLINE_STATUS).c_str());
			_privacyIDEA.OfflineRefillFIDO(username, serialUsed);
			_config->useOfflineFIDO = false;
			return S_OK;
		}
	}

	// Passkey & WebAuthn
	HRESULT hr = FIDO_ERR_INTERNAL;
	bool processingOnline = false;

	if (_config->usePasskey && _config->mode > Mode::SEC_KEY_ANY)
	{
		if (!_passkeyChallenge) { return E_FAIL; }
		hr = device.Sign(_passkeyChallenge.value(), origin, pin, signResponse);
		processingOnline = true;
	}
	else if (_config->lastResponseWithChallenge && _config->lastResponseWithChallenge->GetFIDOSignRequest() && !_privacyIDEASuccess)
	{
		PIDebug("Trying online WebAuthn...");
		hr = device.Sign(_config->lastResponseWithChallenge->GetFIDOSignRequest().value(), origin, pin, signResponse);
		processingOnline = true;
	}

	if (processingOnline)
	{
		if (hr != S_OK)
		{
			PIError("Signing failed with error: " + to_string(hr));
			if (hr == FIDO_ERR_TX) hr = FIDO_DEVICE_ERR_TX;
			_lastStatus = hr;
			if (hr != FIDO_ERR_NO_CREDENTIALS) SetMode(Mode::PRIVACYIDEA);
			return E_FAIL;
		}

		if (signResponse.assertions.empty())
		{
			PIError("Assertion success but list is empty!");
			_lastStatus = FIDO_ERR_NO_CREDENTIALS;
			return E_FAIL;
		}

		// Get the usernames if there are multiple assertions
		if (signResponse.assertions.size() > 1)
		{
			PIDebug("Multiple credentials found: " + to_string(signResponse.assertions.size()));
			bool missingNames = false;
			for (const auto& a : signResponse.assertions)
			{
				if (a.username.empty()) { missingNames = true; break; }
			}

			// If names are missing and we dont have a PIN yet, we MUST ask for it 
			// to resolve the "Unknown User" labels, even if the server said "discouraged".
			if (missingNames && pin.empty())
			{
				PIDebug("Metadata missing due to lack of PIN. Switching to SEC_KEY_PIN to resolve names.");

				// Set mode to PIN so the UI asks for it
				SetMode(Mode::SEC_KEY_PIN);

				// Reset status so we don't show a generic error
				_lastStatus = S_OK;

				// Return failure to abort this connection attempt and display the PIN field
				return E_FAIL;
			}

			// Sort alphabetically by Display Name / Username
			std::sort(signResponse.assertions.begin(), signResponse.assertions.end(),
				[](const FIDOAssertionData& a, const FIDOAssertionData& b) {
					// Compare Display Name if available, otherwise Username
					std::string nameA = a.displayName.empty() ? a.username : a.displayName;
					std::string nameB = b.displayName.empty() ? b.username : b.displayName;

					// Case-insensitive string comparison
					return _stricmp(nameA.c_str(), nameB.c_str()) < 0;
				});

			_currentSignResponse = signResponse;
			_selectedAssertionIndex = 0;

			SetMode(Mode::SEC_KEY_SELECT_USER);

			// Population of the combobox for username selection
			// We must manually populate it because GetComboBoxValueCount won't be called by Windows
			// since we arent triggering a credential re-enumeration (because that would lead to more logic needed).
			if (_pCredProvCredentialEvents)
			{
				// Just append items, assuming this happens only once per authentication attempt, so the combobox is empty.
				for (const auto& assertion : signResponse.assertions)
				{
					std::string label = assertion.displayName;
					if (label.empty()) label = assertion.username;
					if (label.empty()) label = "Unknown User";

					// Add item to UI
					_pCredProvCredentialEvents->AppendFieldComboBoxItem(this, FID_USER_SELECT, Convert::ToWString(label).c_str());
				}

				// Select the first item
				_pCredProvCredentialEvents->SetFieldComboBoxSelectedItem(this, FID_USER_SELECT, 0);
			}

			return E_FAIL;
		}

		// Single user: Proceed automatically
		PIResponse response;
		// Use correct transaction ID based on mode
		std::string transId = _config->usePasskey ? _passkeyChallenge.value().transactionId : _config->lastTransactionId;

		hr = _privacyIDEA.ValidateCheckFIDO(username, domain, signResponse.assertions[0], signResponse.clientdata, origin, response, transId, std::wstring());

		if (SUCCEEDED(hr))
		{
			if (response.username)
			{
				PIDebug("Authentication successful, using username " + response.username.value());
				_config->credential.username = Convert::ToWString(response.username.value());
			}
			EvaluateResponse(response);
			if (_config->usePasskey) _config->usePasskey = false;
			return S_OK;
		}
	}

	return S_OK;
}

HRESULT CCredential::FIDORegistration(IQueryContinueWithStatus* pqcws)
{
	PIDebug("FIDO2 registration with mode " + _config->ModeString());
	HRESULT hr = S_OK;

	if (!pqcws)
	{
		return E_POINTER;
	}

	if (_config->lastResponseWithChallenge && !_config->lastResponseWithChallenge->passkeyRegistration)
	{
		PIError("No passkey registration available, cannot continue with registration");
		return E_FAIL;
	}

	const auto& request = _config->lastResponseWithChallenge->passkeyRegistration.value();

	// RP ID check
	if (!IsRpIdAllowed(request.rpId))
	{
		SetMode(Mode::PRIVACYIDEA);
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

	// Check if the device needs a PIN set
	if (!dev->HasPin())
	{
		PIDebug("Device detected but has no PIN set.");

		// User has already entered the new PIN (We are in the SET_PIN mode)
		if (_config->mode == Mode::SEC_KEY_SET_PIN)
		{
			std::wstring newPin1 = _config->provider.field_strings[FID_NEW_PIN_1];
			std::wstring newPin2 = _config->provider.field_strings[FID_NEW_PIN_2];

			if (newPin1.empty() || newPin1 != newPin2)
			{
				_lastStatus = FIDO_PINS_DO_NOT_MATCH;
				return E_FAIL; // Stay in this mode to let user retry
			}

			try
			{
				pqcws->SetStatusMessage(L"Setting PIN on device...");

				dev->SetPin(Convert::ToString(newPin1));

				// Update the credential config so the Registration call below uses this new PIN immediately.
				_config->credential.fido2PIN = newPin1;

				PIDebug("PIN set successfully. Proceeding to registration...");
			}
			catch (FIDOException ex)
			{
				PIError("Failed to set PIN: " + std::string(ex.what()));
				ShowErrorMessage(Convert::ToWString(ex.what()));
				return E_FAIL;
			}
		}
		// The device has no PIN, switch mode
		else
		{
			SetMode(Mode::SEC_KEY_SET_PIN);
			// Return failure to stop the current Connect() attempt and wait for user input
			return E_FAIL;
		}
	}
	else
	{
		// If we are in SET_PIN mode but the device has a PIN, 
		// the user might have swapped keys or set it elsewhere. Revert to standard PIN entry.
		if (_config->mode == Mode::SEC_KEY_SET_PIN)
		{
			SetMode(Mode::SEC_KEY_REG_PIN);
			return E_FAIL;
		}

		// Now we know the device has a PIN, so we require the user to enter it.
		if (!_config->isRemoteSession && _config->credential.fido2PIN.empty())
		{
			PIDebug("Device has PIN. Requesting fido2 PIN for registration.");
			SetMode(Mode::SEC_KEY_REG_PIN);
			return E_FAIL;
		}
	}

	pqcws->SetStatusMessage(_util.GetText(TEXT_PASSKEY_REGISTER_TOUCH).c_str());

	std::optional<FIDORegistrationResponse> response = std::nullopt;
	try
	{
		response = dev->Register(_config->lastResponseWithChallenge->passkeyRegistration.value(), Convert::ToString(_config->credential.fido2PIN));
	}
	catch (FIDOException ex)
	{
		PIError("FIDO2 registration failed: " + std::string(ex.what()));
		_lastStatus = ex.getErrorCode();
		if (ex.getErrorCode() == FIDO_ERR_PIN_INVALID)
		{
			// Just try again
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

		hr = E_FAIL;
	}

	if (response)
	{
		PIResponse piresponse;
		hr = _privacyIDEA.ValidateCheckCompletePasskeyRegistration(request.transactionId, request.serial,
			_config->credential.username, _config->credential.domain, response.value(), request.rpId, piresponse);

		if (SUCCEEDED(hr) && piresponse.isAuthenticationSuccessful())
		{
			PIDebug("passkey enrollment complete!");
			hr = EvaluateResponse(piresponse);
		}
		else
		{
			hr = E_FAIL;
		}
	}

	return hr;
}

std::wstring CCredential::ResolveUpnToNetBios(const std::wstring& upn)
{
	// If no '@', it's not a UPN, return as-is.
	if (upn.find(L"@") == std::wstring::npos)
	{
		return upn;
	}

	// Get the required buffer size
	// NameUserPrincipal = UPN (user@dns.com)
	// NameSamCompatible = NetBIOS (DOMAIN\User)
	DWORD size = 0;
	BOOLEAN status = TranslateNameW(upn.c_str(), NameUserPrincipal, NameSamCompatible, NULL, &size);

	// ERROR_INSUFFICIENT_BUFFER is expected because we passed NULL to get the size
	if (!status && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		PIDebug("TranslateNameW failed to resolve UPN. Error: " + std::to_string(GetLastError()));
		return upn; // Fallback: return original string on failure (e.g. offline)
	}

	if (size == 0) return upn;

	// Allocate buffer (size includes null terminator in some versions, but vector handles it safely) and translate name
	std::vector<wchar_t> buffer(size);
	status = TranslateNameW(upn.c_str(), NameUserPrincipal, NameSamCompatible, buffer.data(), &size);

	if (!status)
	{
		PIDebug("TranslateNameW execution failed. Error: " + std::to_string(GetLastError()));
		return upn;
	}

	// Convert to wstring (buffer data is null-terminated by API)
	std::wstring result(buffer.data());
	PIDebug(L"Resolved UPN '" + upn + L"' to '" + result + L"'");

	return result;
}

HRESULT CCredential::EvaluateResponse(PIResponse& response)
{
	_config->lastResponse = response;

	wstring username = _config->credential.username;
	wstring domain = _config->credential.domain;
	// Leave the UPN empty if it should not be used
	wstring upn = _config->piconfig.sendUPN ? _config->credential.upn : L"";

	// Always show the OTP field, if push was triggered, start polling in background
	if (response.IsPushAvailable())
	{
		// When polling finishes, pushAuthenticationCallback is invoked with the finalization success value
		_privacyIDEA.PollTransactionAsync(username, domain, upn, response.transactionId,
			std::bind(&CCredential::PushAuthenticationCallback, this, std::placeholders::_1));
	}

	// Save the lastTransactionId, so that the lastResponse can be overwritten with an error response and we still have the transactionId
	if (!response.transactionId.empty())
	{
		_config->lastTransactionId = response.transactionId;
		_enrollmentInProgress = false;
	}

	// Check if we have standard challenges OR a passkey registration request
	if (!response.challenges.empty() || response.passkeyRegistration.has_value())
	{
		// Save the response so Connect() can find it later for FIDO Registration
		_config->lastResponseWithChallenge = response;

		// Only process images/challenge flags if we actually have standard challenges
		if (!response.challenges.empty())
		{
			// Only one image can be displayed so take the first challenge
			// In the main use-case, token enrollment, there will only be a single challenge
			// because the enrollment is only happening after the authentication is completed
			auto& challenge = response.challenges.at(0);

			// enroll_via_multichallenge setup, implicitly means there is only one challenge
			if (!challenge.image.empty())
			{
				// Remove the leading "data:image/png;base64,"
				auto base64image = challenge.image.substr(IMAGE_BASE64_PREFIX.length(), challenge.image.size());
				if (!base64image.empty())
				{
					auto hBitmap = CreateBitmapFromBase64PNG(Convert::ToWString(base64image));
					if (hBitmap != nullptr)
					{
						// TODO add mode enrollment?
						_pCredProvCredentialEvents->SetFieldBitmap(this, FID_LOGO, hBitmap);
					}
					else
					{
						PIDebug("Conversion to bitmap failed, image will not be displayed.");
					}
				}
			}

			if (challenge.type == "push" || challenge.type == "smartphone")
			{
				_pollEnrollmentInProgress = true;
			}
			else
			{
				_enrollmentInProgress = true;
			}
		}
		// If it is a registration, mark enrollment as in progress so UI doesn't reset unexpectedly
		else if (response.passkeyRegistration.has_value())
		{
			_enrollmentInProgress = true;
		}
	}
	else
	{
		_privacyIDEASuccess = response.isAuthenticationSuccessful();
	}

	return S_OK;
}

std::optional<FIDODevice> CCredential::WaitForFIDODevice(IQueryContinueWithStatus* pqcws, int timeoutMs)
{
	PIDebug("No FIDO2 device found, waiting for device");
	if (pqcws)
	{
		pqcws->SetStatusMessage(_util.GetText(TEXT_FIDO_WAITING_FOR_DEVICE).c_str());
	}

	// In CPUS_CREDUI, pqcws is of no use. Disable UI elements and change the large text to the message 
	// to indicate what the user should do.
	if (_config->provider.cpu == CPUS_CREDUI)
	{
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, _util.GetText(TEXT_FIDO_WAITING_FOR_DEVICE).c_str());
		_pCredProvCredentialEvents->SetFieldState(this, FID_LARGE_TEXT, CPFS_DISPLAY_IN_BOTH);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_PASSWORD, CPFIS_DISABLED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_DISABLED);
	}

	// Check for devices
	std::vector<FIDODevice> devices;
	std::optional<FIDODevice> ret = std::nullopt;
	int tries = static_cast<int>(std::ceil(static_cast<double>(timeoutMs) / 200.0));
	const bool filterWindowsHello = !_config->isRemoteSession;
	while (tries > 0)
	{
		this_thread::sleep_for(chrono::milliseconds(200));
		if (pqcws->QueryContinue() != S_OK)
		{
			PIDebug("User cancelled device search");
			_fidoDeviceSearchCancelled = true;
			return std::nullopt;
		}

		auto dev = GetPreferredFIDODevice();
		if (dev.has_value())
		{
			PIDebug("WaitForFIDODevice: Found " + dev->GetProduct());
			return dev;
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

	// Handle User Selection Submission
	if (_config->mode == Mode::SEC_KEY_SELECT_USER)
	{
		if (_selectedAssertionIndex < _currentSignResponse.assertions.size())
		{
			auto& assertion = _currentSignResponse.assertions[_selectedAssertionIndex];

			std::string transactionId = _config->lastTransactionId;
			if (_config->usePasskey && _passkeyChallenge.has_value())
			{
				transactionId = _passkeyChallenge->transactionId;
			}

			// Use the clientData from the container and the assertion data from the specific item
			PIResponse response;
			HRESULT hr = _privacyIDEA.ValidateCheckFIDO(
				Convert::ToWString(assertion.username),
				_config->credential.domain,
				assertion,
				_currentSignResponse.clientdata,
				Convert::ToString(Utilities::ComputerName()),
				response,
				transactionId,
				std::wstring()
			);

			if (SUCCEEDED(hr))
			{
				if (response.username) _config->credential.username = Convert::ToWString(response.username.value());
				EvaluateResponse(response);
				_privacyIDEASuccess = true;
			}
			else
			{
				// Handle error
				ShowErrorMessage(L"Authentication failed.");
			}
		}
		return S_OK;
	}

	if (_config->mode == Mode::PASSWORD && _config->provider.cpu != CPUS_UNLOCK_WORKSTATION)
	{
		PIDebug("Mode is PASSWORD in Logon/CredUI, skipping Connect");
		return S_OK;
	}

	if (CheckExcludedAccount())
	{
		_privacyIDEASuccess = true;
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
	if (_config->IsModeOneOf(Mode::USERNAME, Mode::USERNAMEPASSWORD)
		|| (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && _config->mode == Mode::PASSWORD))
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


	// PRE-FLIGHT REFILL
	// Validate offline credentials against the server before usage. Only of the user or all if configured.
	// Run this if we are about to use FIDO, OR if the admin forces a global check
	const bool isFidoMode = _config->useOfflineFIDO || _config->mode > Mode::SEC_KEY_ANY;
	const bool shouldCheck = (isSendRequest && !username.empty() && isFidoMode);

	if (shouldCheck)
	{
		std::vector<OfflineData> tokensToCheck;

		if (_config->checkAllOfflineCredentials)
		{
			PIDebug("Configured to check ALL offline credentials (global hygiene).");
			// Get EVERY token on the machine (including expired ones)
			tokensToCheck = _privacyIDEA.offlineHandler.GetAllFIDOData(true);
		}
		else
		{
			PIDebug("Checking offline credentials for current user only.");
			std::string szUser = Convert::ToString(username);
			// Get only THIS user's tokens (including expired ones)
			tokensToCheck = _privacyIDEA.offlineHandler.GetFIDODataFor(szUser, true);
		}

		if (!tokensToCheck.empty())
		{
			if (_config->useOfflineFIDO)
			{
				// Give user feedback if we are in a visible offline flow
				pqcws->SetStatusMessage(_util.GetText(TEXT_FIDO_CHECKING_OFFLINE_STATUS).c_str());
			}

			int checkedCount = 0;
			for (const auto& item : tokensToCheck)
			{
				// Optimization: If we are checking ALL tokens, we might process the same user multiple times.
				// The overhead is network-bound, so the loop is fine.
				_privacyIDEA.OfflineRefillFIDO(Convert::ToWString(item.username), item.serial);
				checkedCount++;
			}
			PIDebug("Pre-flight check completed for " + to_string(checkedCount) + " tokens.");
		}

		// Even if we checked everyone, we only disable Offline Mode if the CURRENT user lost their data.
		if (!_privacyIDEA.OfflineFIDODataExistsFor(username))
		{
			PIDebug("Offline data for current user is invalid. Disabling offline mode.");
			if (_config->useOfflineFIDO)
			{
				_config->useOfflineFIDO = false;
			}
		}
	}

	// Send a request to privacyIDEA, try offline authentication or fido2, depending on what happened before
	if (isSendRequest)
	{
		HRESULT hr = E_FAIL;
		// Offline OTP check
		if (isOfflineCheck && (_config->mode < Mode::SEC_KEY_ANY))
		{
			string serialUsed;
			hr = _privacyIDEA.OfflineCheck(username, passToSend, serialUsed);
			// Check if a OfflineRefill should be attempted. Either if offlineThreshold is not set, remaining OTPs are below the threshold, or no more OTPs are available.
			if ((hr == S_OK && _config->offlineTreshold == 0)
				|| (hr == S_OK && _privacyIDEA.offlineHandler.GetOfflineOTPCount(Convert::ToString(username), serialUsed) < _config->offlineTreshold)
				|| hr == PI_OFFLINE_DATA_NO_OTPS_LEFT)
			{
				pqcws->SetStatusMessage(_util.GetText(TEXT_OFFLINE_REFILL).c_str());
				const HRESULT refillResult = _privacyIDEA.OfflineRefill(username, passToSend, serialUsed);
				if (refillResult != S_OK)
				{
					PIDebug("OfflineRefill failed " + Convert::LongToHexString(refillResult));
				}
			}

			// Authentication is complete if offlineCheck succeeds, regardless of refill status
			if (hr == S_OK)
			{
				_privacyIDEASuccess = true;
			}
		}

		// FIDO Authentication
		if (!_privacyIDEASuccess && _config->IsModeOneOf(Mode::SEC_KEY_NO_PIN, Mode::SEC_KEY_PIN, Mode::SEC_KEY_NO_DEVICE)
			&& ((_config->lastResponseWithChallenge && !_config->lastResponseWithChallenge->passkeyRegistration) || _config->usePasskey || _config->useOfflineFIDO))
		{
			hr = FIDOAuthentication(pqcws);
			if (FAILED(hr))
			{
				return hr;
			}
		}
		// FIDO Registration
		else if (!_privacyIDEASuccess && _config->IsModeOneOf(Mode::SEC_KEY_REG, Mode::SEC_KEY_REG_PIN, Mode::SEC_KEY_NO_DEVICE, Mode::SEC_KEY_SET_PIN)
			&& _config->lastResponseWithChallenge && _config->lastResponseWithChallenge->passkeyRegistration)
		{
			if (!_passkeyRegistrationFailed)
			{
				hr = FIDORegistration(pqcws);
				if (SUCCEEDED(hr))
				{
					_privacyIDEASuccess = true;
				}
			}
			else
			{
				SetMode(Mode::PRIVACYIDEA);
				hr = E_FAIL;
			}
			return hr;
		}
		else if (!_privacyIDEASuccess) // OTP
		{
			PIResponse otpResponse;
			// lastTransactionId can be empty
			hr = _privacyIDEA.ValidateCheck(username, domain, passToSend, otpResponse, _config->lastTransactionId, upn);

			// Evaluate the response
			if (SUCCEEDED(hr))
			{
				EvaluateResponse(otpResponse);
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
					_lastStatus = hr;
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

	// Detect Fast User Switching / Profile Lock issue
	if (ntsStatus == 0xC00000DA) // STATUS_USER_MAPPED_FILE_SYSTEM
	{
		PIDebug("ERROR: Password change failed with STATUS_USER_MAPPED_FILE_SYSTEM.");
		PIDebug("CAUSE: The user profile or registry hive is locked by another process.");
		PIDebug("SOLUTION: This is often caused by Fast User Switching or background services. A system reboot is required to clear the lock.");

		if (pcpsiOptionalStatusIcon)
		{
			*pcpsiOptionalStatusIcon = CPSI_ERROR;
		}

		if (ppwszOptionalStatusText)
		{
			std::wstring msg = L"System Error: User profile is locked. Please restart the computer.";
			SHStrDupW(msg.c_str(), ppwszOptionalStatusText);
		}

		return S_OK;
	}

	// These status require a complete reset so that there will be no lock out in 2nd step
	if (ntsStatus == STATUS_LOGON_FAILURE || ntsStatus == STATUS_LOGON_TYPE_NOT_GRANTED
		|| (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus != STATUS_PASSWORD_EXPIRED))
	{
		PIDebug("Complete reset!");
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
