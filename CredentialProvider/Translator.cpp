#include "Translator.h"
#include <codecvt> 
#include <fstream>
#include <locale>
#include <Logger.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <Windows.h>

using namespace std;
using json = nlohmann::json;

RegistryReader rr(CONFIG_REGISTRY_PATH); // Gets registry keys
std::wstring Translator::_localesPath = rr.GetWString(L"localesPath"); // Get locales path

std::unordered_map<int, std::wstring> Translator::_translations;
std::string Translator::_currentLanguage;
std::string Translator::_currentRegion;

Translator::Translator()
{
	_currentLanguage = GetUserLocale();
	SetLanguage(_currentLanguage);
};

void Translator::SetLanguage(const std::string& language)
{
	std::string languageOnly = GetLanguageFromLocale(language);
	std::string region = GetRegionFromLocale(language);
	PIDebug("Translation language " + languageOnly + ", region " + region);
	if (TryLoadTranslations(languageOnly, region))
	{
		_currentLanguage = languageOnly;
		_currentRegion = region;
	}
	else if (TryLoadTranslations(languageOnly))
	{
		_currentLanguage = languageOnly;
		_currentRegion.clear();
	}
	else
	{
		// Fallback to English
		TryLoadTranslations("en");
		_currentLanguage = "en";
		_currentRegion.clear();
	}
}

std::wstring Translator::Translate(int textId)
{
	const auto it = _translations.find(textId);
	if (it != _translations.end())
	{
		return it->second; // Return the translated wstring
	}
	// If translation not found, return "undefined"
	return L"undefined";
}

std::string Translator::GetLanguage()
{
	return _currentLanguage;
}

std::string Translator::GetRegion()
{
	return _currentRegion;
}

std::string Translator::GetUserLocale()
{
	wchar_t localeName[LOCALE_NAME_MAX_LENGTH] = { 0 };
	if (GetUserDefaultLocaleName(localeName, LOCALE_NAME_MAX_LENGTH) != 0)
	{
		char narrowLocaleName[LOCALE_NAME_MAX_LENGTH] = { 0 };
		if (WideCharToMultiByte(CP_UTF8, 0, localeName, -1, narrowLocaleName, LOCALE_NAME_MAX_LENGTH, nullptr, nullptr) > 0)
		{
			return narrowLocaleName;
		}
	}
	// Return fallback language "en" if failed to detect user locale
	return "en";
}

bool Translator::TryLoadTranslations(const std::string& language, const std::string& region)
{
	std::string locale = language;
	if (!region.empty())
	{
		locale += "_" + region;
	}
	return LoadTranslations(locale);
}

bool Translator::LoadTranslations(const std::string& locale)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::string path = converter.to_bytes(_localesPath);

	std::string filePath = path + "\\" + locale + ".json";
	std::ifstream file(filePath);

	//PIDebug("Trying to open translation from " + filePath);
	if (!file.is_open())
	{
		PIDebug("Can not load translation file: " + filePath);
		return false;
	}

	json data{};

	try
	{
		file >> data;
	}
	catch (const std::exception& e)
	{
		UNREFERENCED_PARAMETER(e);
		PIDebug("Error parsing translation file:" + filePath);
		return false;
	}

	PIDebug("Loading translation from " + filePath);

	_translations.clear(); // Clear existing _translations
	for (auto it = data.begin(); it != data.end(); ++it)
	{
		const int key = std::stoi(it.key());
		std::string value = it.value();
		//PIDebug("Loading translation: " + it.key() + ":" + value);
		_translations[key] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(value);
	}
	return true;
}

std::string Translator::GetLanguageFromLocale(const std::string& locale)
{
	// Regular expression to match language part of the locale string
	std::regex languageRegex("([a-z]{2})");
	std::smatch match;
	if (std::regex_search(locale, match, languageRegex))
	{
		return match[1].str();
	}
	// Return empty string if language part not found
	return "";
}

std::string Translator::GetRegionFromLocale(const std::string& locale)
{
	// Regular expression to match region part of the locale string
	std::regex regionRegex("[a-z]{2}[_-]([A-Z]{2})");
	std::smatch match;
	if (std::regex_search(locale, match, regionRegex))
	{
		return match[1].str();
	}
	// Return empty string if region part not found
	return "";
}
