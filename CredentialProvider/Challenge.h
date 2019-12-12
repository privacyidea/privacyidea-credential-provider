#pragma once

#include <string>

class Challenge
{
public:
	Challenge(std::string message, std::string transactionID, std::string serial, std::string type) : 
		message(message), transactionID(transactionID), serial(serial), type(type) {};

	~Challenge() = default;

	std::string message;
	std::string transactionID;
	std::string serial;
	std::string type;
};
