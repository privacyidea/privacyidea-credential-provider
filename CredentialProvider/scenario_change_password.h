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

#ifndef _SCENARIO_CHANGE_PASSWORD
#define _SCENARIO_CHANGE_PASSWORD
#pragma once

#include "field_state_pair.h"
#include "field_initializor.h"

enum CHANGE_PASSWORD_FIELD_ID
{
	CPFI_OTP_LOGO = 0,
	CPFI_OTP_LARGE_TEXT = 1,
	CPFI_OTP_SMALL_TEXT = 2,
	CPFI_OTP_PASS_OLD = 3,
	CPFI_OTP_PASS_NEW_1 = 4,
	CPFI_OTP_PASS_NEW_2 = 5,
	CPFI_OTP_SUBMIT_BUTTON = 6,
	CPFI_NUM_FIELDS = 7,
};

static const FIELD_INITIALIZOR s_rgScenarioChangePasswordFieldInitializors[] =
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
static const FIELD_STATE_PAIR s_rgScenarioChangePasswordFieldStatePairs[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// CPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// CPFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// CPFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// CPFI_OTP_PASS_OLD
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// CPFI_OTP_PASS_NEW_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// CPFI_OTP_PASS_NEW_2
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// CPFI_OTP_SUBMIT_BUTTON
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgScenarioChangePasswordCredProvFieldDescriptors[] =
{
	{ CPFI_OTP_LOGO, CPFT_TILE_IMAGE, L"Logo" },
	{ CPFI_OTP_LARGE_TEXT, CPFT_LARGE_TEXT, L"LargeText" },
	{ CPFI_OTP_SMALL_TEXT, CPFT_SMALL_TEXT, L"SmallText" },
	{ CPFI_OTP_PASS_OLD, CPFT_PASSWORD_TEXT, L"Old Password" },
	{ CPFI_OTP_PASS_NEW_1, CPFT_PASSWORD_TEXT, L"New password" },
	{ CPFI_OTP_PASS_NEW_2, CPFT_PASSWORD_TEXT, L"Retype new password" },
	{ CPFI_OTP_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
};

#endif
