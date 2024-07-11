#pragma once
#include "RegistryReader.h"
#include <unordered_map>
#include <string>

#define PITranslate(messageId)				Translator::GetInstance().Translate(messageId)

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

    static std::unordered_map<int, std::wstring> _translations;
    static std::string _currentLanguage;
    static std::string _currentRegion;
    static std::wstring _localesPath;

    bool TryLoadTranslations(const std::string& language, const std::string& region = "");
    bool LoadTranslations(const std::string& locale);
    
    std::string GetLanguageFromLocale(const std::string& locale);
    std::string GetRegionFromLocale(const std::string& locale);
};
