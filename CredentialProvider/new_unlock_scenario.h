#pragma once
#include "field_state_pair.h"

// The indexes of each of the fields in our credential provider's appended tiles.
enum LOGON_PUSH_FIELD_ID
{
	LPFI_OTP_LOGO = 0,
	LPFI_OTP_LARGE_TEXT = 1,
	LPFI_OTP_SMALL_TEXT = 2,
	LPFI_OTP_USERNAME = 3,
	LPFI_OTP_LDAP_PASS = 4,
	LPFI_OTP_PASS = 5,
	LPFI_OTP_SUBMIT_BUTTON = 6,
	LPFI_OTP_OFFLINE_CHECKBOX = 7,
	LPFI_NUM_FIELDS = 8,
};

// Default values
static const FIELD_INITIALIZOR s_rgScenarioPushFieldInitializors[] =
{
	{ FIT_NONE, NULL },										// LPFI_OTP_LOGO
	{ FIT_VALUE_OR_LOGIN_TEXT, L"" },						// LPFI_OTP_LARGE_TEXT
	{ FIT_VALUE_OR_LOCKED_TEXT, L"" },						// LPFI_OTP_SMALL_TEXT
	{ FIT_USERNAME_AND_DOMAIN, L"" },						// LPFI_OTP_USERNAME
	{ FIT_VALUE, L"" },										// LPFI_OTP_LDAP_PASS
	{ FIT_VALUE, L"" },										// LPFI_OTP_PASS
	{ FIT_VALUE, L"Submit" },								// LPFI_OTP_SUBMIT_BUTTON
	{ FIT_VALUE, L"Use offline token."},					// LPFI_OTP_OFFLINE_CHECKBOX
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs 
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when 
static const FIELD_STATE_PAIR s_rgScenarioPushFieldStatePairs[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LPFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SUBMIT_BUTTON
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_OFFLINE_CHECKBOX
};

static const FIELD_STATE_PAIR s_rgScenarioPushFieldStatePairsUnlock[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LPFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SUBMIT_BUTTON
	{ CPFS_HIDDEN, CPFIS_NONE },			// LPFI_OTP_OFFLINE_CHECKBOX
};

static const FIELD_STATE_PAIR s_rgScenarioPushFieldStatePairsTwoStepSecondStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_USERNAME
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LPFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SUBMIT_BUTTON
	{ CPFS_HIDDEN, CPFIS_NONE },			// LPFI_OTP_OFFLINE_CHECKBOX
};

static const FIELD_STATE_PAIR s_rgScenarioPushFieldStatePairsTwoStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LPFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SUBMIT_BUTTON
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_OFFLINE_CHECKBOX
};

static const FIELD_STATE_PAIR s_rgScenarioPushFieldStatePairsUnlockTwoStep[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// LPFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// LPFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// LPFI_OTP_SUBMIT_BUTTON
	{ CPFS_HIDDEN, CPFIS_NONE },							// LPFI_OTP_OFFLINE_CHECKBOX
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgScenarioPushCredProvFieldDescriptors[] =
{
	{ LPFI_OTP_LOGO, CPFT_TILE_IMAGE, L"Logo" },
	{ LPFI_OTP_LARGE_TEXT, CPFT_LARGE_TEXT, L"LargeText" },
	{ LPFI_OTP_SMALL_TEXT, CPFT_SMALL_TEXT, L"SmallText" },
	{ LPFI_OTP_USERNAME, CPFT_EDIT_TEXT, L"Username" },
	{ LPFI_OTP_LDAP_PASS, CPFT_PASSWORD_TEXT, L"Password" },
	{ LPFI_OTP_PASS, CPFT_PASSWORD_TEXT, L"One-Time Password" },
	{ LPFI_OTP_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
	{ LPFI_OTP_OFFLINE_CHECKBOX, CPFT_CHECKBOX, L"UseOffline"},
};

static PWSTR s_rgScenarioPushComboBoxModeStrings[] =
{
	L"Nothing", // default
};
