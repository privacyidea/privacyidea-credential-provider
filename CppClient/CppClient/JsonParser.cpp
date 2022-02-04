#include "JsonParser.h"
#include "../nlohmann/json.hpp"
#include "Logger.h"

using json = nlohmann::json;

PIResponse JsonParser::parsePIResponse(std::string serverResponse)
{
	PIResponse response;
	json j;
	try
	{
		j = json::parse(serverResponse);
		return response;
	}
	catch (const json::parse_error& e)
	{
		DebugPrint(e.what());
		return response;
	}

    return response;
}
