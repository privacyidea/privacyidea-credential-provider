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

	conf->ssl_verify_hostname = 0;
	conf->ssl_verify_signature = 0;

	ZERO(conf->v1_bitmap_path);
	ZERO(conf->v2_bitmap_path);
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

	readRegistryValueString(CONF_V1_BITMAP_PATH, sizeof(conf->v1_bitmap_path), conf->v1_bitmap_path);
	readRegistryValueString(CONF_V2_BITMAP_PATH, sizeof(conf->v2_bitmap_path), conf->v2_bitmap_path);

	if (readRegistryValueString(CONF_SSL_VERIFY_HOSTNAME, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->ssl_verify_hostname = 0; // if NULL
	else 
	{
		conf->ssl_verify_hostname = buffer[0] - 0x30;
	}

	if (readRegistryValueString(CONF_SSL_VERIFY_SIGNATURE, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->ssl_verify_signature = 0; // if NULL
	else 
	{
		conf->ssl_verify_signature = buffer[0] - 0x30;
	}

	if (readRegistryValueString(CONF_TWO_STEP_HIDE_OTP, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->two_step_hide_otp = 0; // if NULL
	else
	{
		conf->two_step_hide_otp = buffer[0] - 0x30;
	}

	if (readRegistryValueString(CONF_TWO_STEP_SEND_PASSWORD, sizeof(buffer), buffer) <= 1) // 1 = size of a char NULL-terminator in byte
		conf->two_step_send_password = 0; // if NULL
	else
	{
		conf->two_step_send_password = buffer[0] - 0x30;
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