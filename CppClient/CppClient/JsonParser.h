#pragma once
#include <string>
#include "PIResponse.h"

class JsonParser
{
public:

	PIResponse parsePIResponse(std::string serverResponse);

};

