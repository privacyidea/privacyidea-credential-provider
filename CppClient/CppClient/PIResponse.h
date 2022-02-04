#pragma once
#include <string>
#include <vector>
#include "Challenge.h"

class PIResponse
{
public:
	bool status = false;
	bool value = false;

	std::string transactionId;
	std::string message;

	std::string errorMessage;
	int errorCode;

	std::vector<Challenge> challenges;
};

