#include "Convert.h"
#include <codecvt>
#include <sstream>
#include <algorithm>

std::wstring Convert::ToWString(const std::string& s)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(s);
}

std::string Convert::ToString(const std::wstring& ws)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(ws);
}

std::string Convert::ToString(const bool b)
{
	return b ? std::string("true") : std::string("false");
}

std::wstring Convert::ToUpperCase(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::toupper(c)); });
	return s;
}

std::string Convert::LongToHexString(long in)
{
	std::stringstream ss;
	ss << std::hex << in;
	return "0x" + ss.str();
}
