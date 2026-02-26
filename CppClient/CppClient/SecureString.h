#pragma once
#include <string>
#include <WinBase.h>

struct SecureWString {
    wchar_t* ptr;
    size_t len;

    SecureWString(const std::wstring& str) {
        len = str.size() + 1;
        ptr = new wchar_t[len];
        wcscpy_s(ptr, len, str.c_str());
    }

    ~SecureWString() {
        if (ptr) {
            SecureZeroMemory(ptr, len * sizeof(wchar_t));
            delete[] ptr;
        }
    }

    SecureWString(const SecureWString&) = delete;
    SecureWString& operator=(const SecureWString&) = delete;
    SecureWString(SecureWString&&) = delete;
    SecureWString& operator=(SecureWString&&) = delete;

    wchar_t* get() const { return ptr; }
};

struct SecureString {
    char* ptr;
    size_t len;

    SecureString(const std::string& str) {
        len = str.size() + 1;
        ptr = new char[len];
        strcpy_s(ptr, len, str.c_str());
    }

    ~SecureString() {
        if (ptr) {
            SecureZeroMemory(ptr, len * sizeof(char));
            delete[] ptr;
        }
    }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    SecureString(SecureString&&) = delete;
    SecureString& operator=(SecureString&&) = delete;

    char* get() const { return ptr; }
};