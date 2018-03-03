#include "registry.h"

DWORD readRegistryValueString(__in LPCSTR value, __in LPCSTR key, __in int buffer_size, __deref_out_opt char* data) 
{
	//char lszValue[1024];
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;
	DWORD dwSize = 0;

	char baseKey[sizeof(REGISTRY_BASE_KEY) / sizeof(char) + 100];
	ZeroMemory(baseKey, sizeof(baseKey));

	strncat_s(baseKey, sizeof(baseKey) / sizeof(char), REGISTRY_BASE_KEY, sizeof(REGISTRY_BASE_KEY));

	if (key && key[0])
	{
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), "\\", sizeof("\\"));
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), key, strlen(key));
	}

	returnStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, baseKey, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = buffer_size;

		returnStatus = RegQueryValueExA(hKey, value, NULL, &dwType, (LPBYTE)data, &dwSize);
		if (returnStatus != ERROR_SUCCESS)
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}

	return dwSize;
}

DWORD readRegistryValueString(__in CONF_VALUE conf_value, __in int buffer_size, __deref_out_opt char* data) 
{
	LPCSTR confValueName = s_CONF_VALUES[conf_value];
	return readRegistryValueString(confValueName, NULL, buffer_size, data);
}

DWORD readRegistryValueInteger(__in LPCSTR value, __in LPCSTR key, __deref_out_opt int* data) 
{
	DWORD lszValue;
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = 0;

	char baseKey[sizeof(REGISTRY_BASE_KEY) / sizeof(char) + 100];
	ZeroMemory(baseKey, sizeof(baseKey));

	strncat_s(baseKey, sizeof(baseKey) / sizeof(char), REGISTRY_BASE_KEY, sizeof(REGISTRY_BASE_KEY));

	if (key && key[0])
	{
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), "\\", sizeof("\\"));
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), key, strlen(key));
	}

	returnStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, baseKey, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = sizeof(DWORD);

		returnStatus = RegQueryValueExA(hKey, value, NULL, &dwType, reinterpret_cast<LPBYTE>(&lszValue), &dwSize);
		if (returnStatus == ERROR_SUCCESS)
		{
			*data = lszValue;
		}
		else
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}

	return dwSize;
}

DWORD readRegistryValueInteger(__in CONF_VALUE conf_value, __deref_out_opt int* data) 
{
	LPCSTR confValueName = s_CONF_VALUES[conf_value];
	return readRegistryValueInteger(confValueName, NULL, data);
}


DWORD readRegistryValueBinary(__in LPCSTR value, __in LPCSTR key, __in int buffer_size, __deref_out_opt unsigned char* data)
{
	//char lszValue[1024];
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_BINARY;
	DWORD dwSize = 0;

	char baseKey[sizeof(REGISTRY_BASE_KEY) / sizeof(char) + 100];
	ZeroMemory(baseKey, sizeof(baseKey));

	strncat_s(baseKey, sizeof(baseKey) / sizeof(char), REGISTRY_BASE_KEY, sizeof(REGISTRY_BASE_KEY));

	if (key && key[0])
	{
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), "\\", sizeof("\\"));
		strncat_s(baseKey, sizeof(baseKey) / sizeof(char), key, strlen(key));
	}

	returnStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, baseKey, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = buffer_size;

		returnStatus = RegQueryValueExA(hKey, value, NULL, &dwType, data, &dwSize);
		if (returnStatus != ERROR_SUCCESS)
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}

	return dwSize;
}

DWORD writeRegistryValueString(__in LPCSTR value, __in LPCSTR key, __in char* data, __in int buffer_size)
{
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;

	returnStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus = RegSetKeyValueA(hKey, key, value, dwType, data, buffer_size);
		RegCloseKey(hKey);
	}

	return returnStatus;
}

DWORD writeRegistryValueString(__in CONF_VALUE conf_value, __in char* data, __in int buffer_size)
{
	LPCSTR confValueName = s_CONF_VALUES[conf_value];
	return writeRegistryValueString(confValueName, NULL, data, buffer_size);
}

DWORD writeRegistryValueInteger(__in LPCSTR value, __in LPCSTR key, __in int data)
{
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_DWORD;

	returnStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus = RegSetKeyValueA(hKey, key, value, dwType, &data, sizeof(int));
		RegCloseKey(hKey);
	}

	return returnStatus;
}

DWORD writeRegistryValueInteger(__in CONF_VALUE conf_value, __in int data)
{
	LPCSTR confValueName = s_CONF_VALUES[conf_value];
	return writeRegistryValueInteger(confValueName, NULL, data);
}

DWORD writeRegistryValueBinary(__in LPCSTR value, __in LPCSTR key, __in unsigned char* data, __in int buffer_size)
{
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_BINARY;

	returnStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus = RegSetKeyValueA(hKey, key, value, dwType, data, buffer_size);
		RegCloseKey(hKey);
	}

	return returnStatus;
}