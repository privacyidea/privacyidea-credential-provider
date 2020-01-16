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

#ifndef _SCENARIO_UNLOCK_LOGON
#define _SCENARIO_UNLOCK_LOGON
#pragma once

#include "field_state_pair.h"

// The indexes of each of the fields in our credential provider's appended tiles.
enum LOGON_UNLOCK_FIELD_ID
{
	LUFI_OTP_LOGO = 0,
	LUFI_OTP_LARGE_TEXT = 1,
	LUFI_OTP_SMALL_TEXT = 2,
	LUFI_OTP_USERNAME = 3,
	LUFI_OTP_LDAP_PASS = 4,
	LUFI_OTP_PASS = 5,
	LUFI_OTP_SUBMIT_BUTTON = 6,
	LUFI_NUM_FIELDS = 7,
};

static const FIELD_INITIALIZOR s_rgScenarioLogonUnlockFieldInitializors[] =
{
	{ FIT_NONE, NULL },
	{ FIT_VALUE_OR_LOGIN_TEXT, L"" },
	{ FIT_VALUE_OR_LOCKED_TEXT, L"" },
	{ FIT_USERNAME_AND_DOMAIN, L"" },
	{ FIT_VALUE, L"" },
	{ FIT_VALUE, L"" },
	{ FIT_VALUE, L"Submit" },
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs 
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when 
static const FIELD_STATE_PAIR s_rgScenarioLogonUnlockFieldStatePairs[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LUFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgScenarioLogonUnlockFieldStatePairsUnlock[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LUFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgScenarioLogonUnlockFieldStatePairsSecondStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_USERNAME
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LUFI_OTP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgScenarioLogonUnlockFieldStatePairsTwoStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LUFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgScenarioLogonUnlockFieldStatePairsUnlockTwoStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LUFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LUFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// LUFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LUFI_OTP_SUBMIT_BUTTON
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgScenarioLogonUnlockCredProvFieldDescriptors[] =
{
	{ LUFI_OTP_LOGO, CPFT_TILE_IMAGE, L"Logo" },
	{ LUFI_OTP_LARGE_TEXT, CPFT_LARGE_TEXT, L"LargeText" },
	{ LUFI_OTP_SMALL_TEXT, CPFT_SMALL_TEXT, L"SmallText" },
	{ LUFI_OTP_USERNAME, CPFT_EDIT_TEXT, L"Username" },
	{ LUFI_OTP_LDAP_PASS, CPFT_PASSWORD_TEXT, L"Password" },
	{ LUFI_OTP_PASS, CPFT_PASSWORD_TEXT, L"One-Time Password" },
	{ LUFI_OTP_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
};

static PWSTR s_rgScenarioLogonUnlockComboBoxModeStrings[] =
{
	L"Nothing", // default
};

#endif
