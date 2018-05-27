#include "config.h"

namespace Configuration
{

CONFIGURATION*& Get()
{
	static struct CONFIGURATION *conf = NULL;

	return conf;
}

void Default()
{
	struct CONFIGURATION*& conf = Get();

	ZERO(conf->server_url);
	ZERO(conf->login_text);
	ZERO(conf->otp_text);
	ZERO(conf->v1_bitmap_path);
	ZERO(conf->v2_bitmap_path);
	
	// DEFAULT IS SAFE MODE, NO ERRORS WILL BE IGNORED 
	conf->ssl_ignore_unknown_ca = 0;
	conf->ssl_ignore_invalid_cn = 0;
}

void Init()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	conf = (struct CONFIGURATION*) malloc(sizeof(struct CONFIGURATION));

	Default();
}

void Deinit()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	Default();

	free(conf);
	conf = NULL;
}

///////////////////// SPECIFIC CONFIGURATION

void Read()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	char buffer[2];

	// Read config
	readRegistryValueString(CONF_SERVER_URL, sizeof(conf->server_url), conf->server_url);

	if (readRegistryValueString(CONF_LOGIN_TEXT, sizeof(conf->login_text), conf->login_text) <= 1) // 1 = size of a char NULL-terminator in byte
		strcpy_s(conf->login_text, sizeof(conf->login_text), CONFIG_DEFAULT_LOGIN_TEXT);

	if (readRegistryValueString(CONF_OTP_TEXT, sizeof(conf->otp_text), conf->otp_text) <= 1) // 1 = size of a char NULL-terminator in byte
		strcpy_s(conf->otp_text, sizeof(conf->otp_text), CONFIG_DEFAULT_OTP_TEXT);

	readRegistryValueString(CONF_V1_BITMAP_PATH, sizeof(conf->v1_bitmap_path), conf->v1_bitmap_path);
	readRegistryValueString(CONF_V2_BITMAP_PATH, sizeof(conf->v2_bitmap_path), conf->v2_bitmap_path);
	
	// HIDE TWO STEP OTP
	if (readRegistryValueString(CONF_TWO_STEP_HIDE_OTP, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->two_step_hide_otp = 0; // if NULL
	else
	{
		conf->two_step_hide_otp = buffer[0] - 0x30;
	}

	// SEND PASSWORD TWO STEP
	if (readRegistryValueString(CONF_TWO_STEP_SEND_PASSWORD, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->two_step_send_password = 0; // if NULL
	else
	{
		conf->two_step_send_password = buffer[0] - 0x30;
	}
	// SSL IGNORE UNKNOWN CA
	if (readRegistryValueString(CONF_SSL_IGNORE_UNKNOWN_CA, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->ssl_ignore_unknown_ca = 0; // if NULL
	else
	{
		conf->ssl_ignore_unknown_ca = buffer[0] - 0x30;
	}

	// SSL IGNORE INVALID CN
	if (readRegistryValueString(CONF_SSL_IGNORE_INVALID_CN, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->ssl_ignore_invalid_cn = 0; // if NULL
	else
	{
		conf->ssl_ignore_invalid_cn = buffer[0] - 0x30;
	}

	// HIDE USERNAME
	if (readRegistryValueString(CONF_HIDE_USERNAME, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->hide_username = 0; // if NULL
	else
	{
		conf->hide_username = buffer[0] - 0x30;
	}
	
	// END
}

DWORD SaveValueString(CONF_VALUE conf_value, char* value, int size)
{
	DebugPrintLn(__FUNCTION__);

	return writeRegistryValueString(conf_value, value, size);
}

DWORD SaveValueInteger(CONF_VALUE conf_value, int value)
{
	DebugPrintLn(__FUNCTION__);

	return writeRegistryValueInteger(conf_value, value);
}

} // Namespace Configuration