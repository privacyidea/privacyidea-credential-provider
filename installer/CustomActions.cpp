// Custom Action for WiX installer to convert semicolon-separated string to REG_MULTI_SZ format

#include <windows.h>
#include <msiquery.h>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "msi.lib")

// Helper to split string by delimiter
std::vector<std::wstring> SplitString(const std::wstring& input, wchar_t delimiter)
{
    std::vector<std::wstring> result;
    std::wstringstream ss(input);
    std::wstring item;

    while (std::getline(ss, item, delimiter))
    {
        // Trim whitespace
        size_t start = item.find_first_not_of(L" \t\r\n");
        size_t end = item.find_last_not_of(L" \t\r\n");

        if (start != std::wstring::npos && end != std::wstring::npos)
        {
            item = item.substr(start, end - start + 1);
            if (!item.empty())
            {
                result.push_back(item);
            }
        }
    }

    return result;
}

// Helper to convert vector to REG_MULTI_SZ format (null-separated, double-null terminated)
std::wstring VectorToMultiSZ(const std::vector<std::wstring>& strings)
{
    std::wstring result;
    for (const auto& str : strings)
    {
        result += str;
        result += L'\0';  // Null separator
    }
    result += L'\0';  // Double-null terminator
    return result;
}

extern "C" __declspec(dllexport) UINT __stdcall SplitSemicolonToMultiSZ(MSIHANDLE hInstall)
{
    WCHAR szBuffer[4096];
    DWORD dwSize;

    // Process EXCLUDED_ACCOUNTS
    dwSize = sizeof(szBuffer) / sizeof(WCHAR);
    if (MsiGetProperty(hInstall, L"EXCLUDED_ACCOUNTS", szBuffer, &dwSize) == ERROR_SUCCESS && dwSize > 0)
    {
        std::vector<std::wstring> accounts = SplitString(szBuffer, L';');
        std::wstring multiSZ = VectorToMultiSZ(accounts);
        MsiSetProperty(hInstall, L"EXCLUDED_ACCOUNTS_MULTISZ", multiSZ.c_str());
    }

    // Process EXCLUDED_GROUPS
    dwSize = sizeof(szBuffer) / sizeof(WCHAR);
    if (MsiGetProperty(hInstall, L"EXCLUDED_GROUPS", szBuffer, &dwSize) == ERROR_SUCCESS && dwSize > 0)
    {
        std::vector<std::wstring> groups = SplitString(szBuffer, L';');
        std::wstring multiSZ = VectorToMultiSZ(groups);
        MsiSetProperty(hInstall, L"EXCLUDED_GROUPS_MULTISZ", multiSZ.c_str());
    }

    // Process DOMAIN_CONTROLLERS
    dwSize = sizeof(szBuffer) / sizeof(WCHAR);
    if (MsiGetProperty(hInstall, L"DOMAIN_CONTROLLERS", szBuffer, &dwSize) == ERROR_SUCCESS && dwSize > 0)
    {
        std::vector<std::wstring> dcs = SplitString(szBuffer, L';');
        std::wstring multiSZ = VectorToMultiSZ(dcs);
        MsiSetProperty(hInstall, L"DOMAIN_CONTROLLERS_MULTISZ", multiSZ.c_str());
    }

    return ERROR_SUCCESS;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}