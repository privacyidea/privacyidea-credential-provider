#ifndef _FIELD_STATE_PAIR
#define _FIELD_STATE_PAIR
#pragma once

#include <credentialprovider.h>

enum SUBMIT_BUTTON_CONTROL
{
	SBC_NONE = 0,
	SBC_THIS = 1,
	SBC_HERE = 2,
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
	CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
	SUBMIT_BUTTON_CONTROL sbc;
};

#endif