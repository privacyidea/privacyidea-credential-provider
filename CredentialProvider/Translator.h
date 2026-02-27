#pragma once
#include "RegistryReader.h"
#include <unordered_map>
#include <string>
#include <shared_mutex>
#include <mutex>

#define PITranslate(messageId)				Translator::GetInstance().Translate(messageId)


// Text IDs
constexpr auto TEXT_USERNAME = 0;
constexpr auto TEXT_PASSWORD = 1;
constexpr auto TEXT_OLD_PASSWORD = 2;
constexpr auto TEXT_NEW_PASSWORD = 3;
constexpr auto TEXT_CONFIRM_PASSWORD = 4;
constexpr auto TEXT_DOMAIN_HINT = 5;
constexpr auto TEXT_OTP_FIELD = 6;
constexpr auto TEXT_WRONG_OTP = 7;
constexpr auto TEXT_RESET_LINK = 8;
constexpr auto TEXT_AVAILABLE_OFFLINE_TOKEN = 9;
constexpr auto TEXT_OTPS_REMAINING = 10;
constexpr auto TEXT_GENERIC_ERROR = 11;
constexpr auto TEXT_USE_ONLINE_FIDO = 12;
constexpr auto TEXT_USE_OTP = 13;
constexpr auto TEXT_FIDO_PIN_HINT = 14;
constexpr auto TEXT_TOUCH_SEC_KEY = 15;
constexpr auto TEXT_CONNECTING = 16;
constexpr auto TEXT_LOGIN_TEXT = 17;
constexpr auto TEXT_OTP_PROMPT = 18;
constexpr auto TEXT_FIDO_NO_CREDENTIALS = 19;
constexpr auto TEXT_FIDO_WAITING_FOR_DEVICE = 20;
constexpr auto TEXT_FIDO_CHECKING_OFFLINE_STATUS = 21;
constexpr auto TEXT_OFFLINE_REFILL = 22;
constexpr auto TEXT_FIDO_ERR_PIN_BLOCKED = 23;
constexpr auto TEXT_FIDO_ERR_TX = 24;
constexpr auto TEXT_FIDO_ERR_PIN_INVALID = 25;
constexpr auto TEXT_USE_PASSKEY = 26;
constexpr auto TEXT_ENTER_USERNAME = 27;
constexpr auto TEXT_ENTER_PASSWORD = 28;
constexpr auto TEXT_ENTER_USERNAME_PASSWORD = 29;
constexpr auto TEXT_PASSKEY_REGISTER_TOUCH = 30;
constexpr auto TEXT_SEC_KEY_ENTER_PIN_PROMPT = 31;
constexpr auto TEXT_PASSKEY_REGISTRATION = 32;
constexpr auto TEXT_LOGIN_WITH_USERNAME = 33;
constexpr auto TEXT_FIDO_CANCELLED = 34;
constexpr auto TEXT_CANCEL_ENROLLMENT = 35;
constexpr auto TEXT_USE_OFFLINE_FIDO = 36;
constexpr auto TEXT_FIDO_ERR_NO_CREDENTIALS = 37;
constexpr auto TEXT_GUIDE_USE_WINDOWS_HELLO = 38;
constexpr auto TEXT_SET_NEW_SEC_KEY_PIN = 39;
constexpr auto TEXT_NEW_PIN_HINT = 40;
constexpr auto TEXT_NEW_PIN_REPEAT_HINT = 41;
constexpr auto TEXT_SELECT_USER = 42;
constexpr auto TEXT_PINS_DO_NOT_MATCH = 43;
constexpr auto TEXT_SETTING_PIN = 44;
constexpr auto TEXT_AUTHENTICATION_FAILED = 45;
constexpr auto TEXT_USER_PROFILE_LOCKED_RESTART_REQUIRED = 46;

// 
// Singleton Translator class that reads language files and use translation methods.
// Sets the current language and loads the locales from file.
// The language file location is in the registry key localesPath
// By default, uses GetUserLocale() to get the current language from Windows. 
// Example: es-AR or es_AR. 
// First looks up for language-region "es_AR", if the file is not found then looks for language "es", and if not found falls back to "en" (english)
// The method Translate(textId), returns the wstring corresponding to the id in the current language.
//  

class Translator final {
public:
    Translator(const Translator&) = delete;
    void operator=(const Translator&) = delete;

    Translator(Translator&&) noexcept = delete;
    Translator& operator=(Translator&&) noexcept = delete;

    ~Translator() = default;

    static Translator& GetInstance() {
        static Translator instance;
        return instance;
    }
            
    void SetLanguage(const std::string& language); 
    std::wstring Translate(int textId); // Translate the textId to the corresponding current language
    std::string GetLanguage(); // Returns current language
    std::string GetRegion();   // Returns current region
    std::string GetUserLocale();

private:
    Translator();
    static std::shared_mutex _mutex;
    static std::unordered_map<int, std::wstring> _translations;
    static std::string _currentLanguage;
    static std::string _currentRegion;
    static std::wstring _localesPath;

    bool TryLoadTranslations(const std::string& language, const std::string& region = "");
    bool LoadTranslations(const std::string& locale);
    
    std::string GetLanguageFromLocale(const std::string& locale);
    std::string GetRegionFromLocale(const std::string& locale);
};
