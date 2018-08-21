#ifndef _CONFIG_H
#define _CONFIG_H
#pragma once

//#include "dependencies.h"

#include "common.h"
#include "helper.h"
#include "registry.h"

#include "../versioning/version.h"

namespace Configuration
{
	#define CONFIG_DEFAULT_LOGIN_TEXT ENDPOINT_NAME" Login"
	#define CONFIG_DEFAULT_OTP_TEXT "One-Time Password"
	#define CONFIG_DEFAULT_EMPTY_PATH ""

	/////////////////// BASE

	struct CONFIGURATION
	{
		char hostname[1024];
		char login_text[64];
		char otp_text[64];

		char v1_bitmap_path[1024];
		char v2_bitmap_path[1024];

		int two_step_hide_otp;
		int two_step_send_password;

		int ssl_ignore_unknown_ca;
		int ssl_ignore_invalid_cn;

		int hide_fullname;
		int hide_domainname;

		int release_log;
		char path[1024];
		int custom_port;

		int two_step_send_empty_password;
	};

	CONFIGURATION*& Get();
	void Default();
	void Init();
	void Deinit();

	////////////////// SPECIFIC

	void Read();
	DWORD SaveValueString(CONF_VALUE conf_value, char* value, int size);
	DWORD SaveValueInteger(CONF_VALUE conf_value, int value);
}

#endif
