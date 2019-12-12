/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2019 NetKnights GmbH
** Author:		Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "OfflineData.h"
#include "nlohmann/json.hpp"
#include <iostream>

using namespace std;
using json = nlohmann::json;

template <class T>
void handleException(T e)
{
	// print the exception
	//e.what()
}

OfflineData::OfflineData(std::string json_string)
{
	json j;
	try
	{
		j = json::parse(json_string);
	}
	catch (json::parse_error & e)
	{
		handleException<json::parse_error>(e);
		return;
	}
	try {
		if (j["count"].is_string())
		{
			try
			{
				count = stoi(j["count"].get<std::string>());
			}
			catch (std::invalid_argument & e)
			{
				handleException<std::invalid_argument>(e);
			}
		}
	}
	catch (json::type_error & e) {
		handleException<json::type_error>(e);
	}


	if (j["refilltoken"].is_string())
	{
		refilltoken = j["refilltoken"].get<std::string>();
	}

	if (j["user"].is_string())
	{
		user = j["user"].get<std::string>();
	}

	if (j["username"].is_string())
	{
		username = j["username"].get<std::string>();
	}

	auto jOTPs = j["response"];
	if (jOTPs != nullptr)
	{
		for (auto& item : jOTPs.items())
		{
			string key = item.key();
			string value = item.value();
			offlineOTPs.try_emplace(key, value);
		}
	}

	// Try to get the serial - if the data is coming from the save file, the serial will be set
	if (j["serial"].is_string())
	{
		serial = j["serial"].get<std::string>();
	}
}

nlohmann::json OfflineData::toJSON()
{
	json j;
	j["count"] = to_string(count);
	j["refilltoken"] = refilltoken;
	j["serial"] = serial;
	j["user"] = user;
	j["username"] = username;

	json jResponse;

	for (auto& item : offlineOTPs)
	{
		jResponse[item.first] = item.second;
	}

	j["response"] = jResponse;

	return j;
}

int OfflineData::getLowestKey()
{
	int ret = 0;
	int lowestKey = INT_MAX;

	for (auto& item : offlineOTPs)
	{
		try
		{
			int key = stoi(item.first);
			lowestKey = (lowestKey > key ? key : lowestKey);
		}
		catch (std::invalid_argument & e)
		{
			handleException<std::invalid_argument>(e);
		}
	}
	ret = lowestKey;

	return ret;
}

int OfflineData::getOfflineOTPsLeft()
{
	return offlineOTPs.size();
}
