#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "Translator.h"
#include <codecvt> 
#include <fstream>
#include <locale>
#include <Logger.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <Windows.h>
#include <Convert.h>

using namespace std;
using json = nlohmann::json;

RegistryReader rr(CONFIG_REGISTRY_PATH);
std::wstring Translator::_localesPath = rr.GetWString(L"locales_path");

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

	_translations.clear();

	// Always load English as the base layer foundation
	LoadTranslations("en");

	if (languageOnly != "en")
	{
		// Layer the target language/region on top (overwrites English keys)
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
			// If target language files are missing entirely, stay with English
			_currentLanguage = "en";
			_currentRegion.clear();
		}
	}
	else
	{
		_currentLanguage = "en";
		_currentRegion.clear();
	}
}

std::wstring Translator::Translate(int textId)
{
	const auto it = _translations.find(textId);
	if (it != _translations.end())
	{
		return it->second;
	}
	// If ID is missing even in the English fallback, return "undefined"
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
	std::string path = Convert::ToString(_localesPath);
	std::string filePath = path + "\\" + locale + ".json";
	std::ifstream file(filePath);

	if (!file.is_open())
	{
		PIDebug("Translation file not found: " + filePath);
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
		PIError("Error parsing translation file: " + filePath);
		return false;
	}

	PIDebug("Merging translations from " + filePath);

	for (auto it = data.begin(); it != data.end(); ++it)
	{
		try {
			const int key = std::stoi(it.key());
			std::string value = it.value();
			_translations[key] = Convert::ToWString(value);
		}
		catch (...) {
			PIError("Invalid key in translation file: " + it.key());
		}
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
