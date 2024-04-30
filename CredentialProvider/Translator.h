
#ifndef TRANSLATOR_H
#define TRANSLATOR_H

#pragma once
#include <unordered_map>
#include <mutex>
#include <string>
#include "RegistryReader.h"

#define PITranslate(messageId)				Translator::getInstance().translate(messageId)

// 
// Singleton Translator class that reads language files and use translation methods.
// Sets the current language and loads the locales from file.
// The language file location is in the registry key localesPath
// By default, uses getUserLocale() to get the current language from Windows. 
// Example: es-AR or es_AR. 
// First looks up for language-region "es_AR", if the file is not found then looks for language "es", and if not found falls back to "en" (english)
// The method translate(textId), returns the wstring corresponding to the id in the current language.
//  

class Translator final {
public:
    Translator(const Translator&) = delete;
    void operator=(const Translator&) = delete;

    Translator(Translator&&) noexcept = delete;
    Translator& operator=(Translator&&) noexcept = delete;

    ~Translator() = default;

    static Translator& getInstance() {
        // Lock mutex for the singleton
        static Translator instance;
        std::lock_guard<std::mutex> lock(_mutex);
        return instance;
    }
            
    void setLanguage(const std::string& language); 
    std::wstring translate(int textId); // Translate the textId to the corresponding current language
    std::string getLanguage(); // Returns current language
    std::string getRegion();   // Returns current region
    std::string getUserLocale();

private:
    Translator();

    static std::unordered_map<int, std::wstring> _translations;
    static std::string _currentLanguage;
    static std::string _currentRegion;
    static std::wstring _localesPath;

    static std::mutex _mutex; 

    bool tryLoadTranslations(const std::string& language, const std::string& region = "");
    bool loadTranslations(const std::string& locale);
    
    std::string getLanguageFromLocale(const std::string& locale);
    std::string getRegionFromLocale(const std::string& locale);
};

#endif // TRANSLATOR_H
