/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
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
#include "Challenge.h"
#include "PrivacyIDEA.h"

const std::vector<std::string> punctuationChars = { "!", "?", ";" ,":", "."};

std::wstring Challenge::getAggregatedMessage()
{
	std::string ret = "";
	for (const auto& m : _messages)
	{
		ret.append(m).append(" or ");
	}
	if (!ret.empty())
	{
		ret = ret.substr(0, ret.size() - 4);
		std::string lastChar = ret.substr(ret.size() - 1, ret.size());
		if (std::find(punctuationChars.begin(), punctuationChars.end(), lastChar) == punctuationChars.end())
		{
			ret.append(":");
		}
	}
	return PrivacyIDEA::s2ws(ret);
}

std::string Challenge::toString()
{
	std::string ret;
	ret = "Challenge: serial=" + serial + ", transaction_id=" + transaction_id + ", tta=" + ttaToString(tta)+ ", messages=";
	for (const auto& m : _messages)
	{
		ret.append(m).append(", ");
	}
	ret = _messages.empty() ? ret : ret.substr(0, ret.size() - 2);
	return ret;
}

void Challenge::addMessage(const std::string& msg)
{
	if (std::find(_messages.begin(), _messages.end(), msg) == _messages.end())
	{
		_messages.push_back(msg);
	}
}

bool Challenge::messagesEmpty()
{
	return _messages.empty();
}

std::string Challenge::ttaToString(TTA tta)
{
	switch (tta)
	{
	case TTA::NOT_SET: return "NOT_SET";
	case TTA::OTP: return "OTP";
	case TTA::PUSH: return "PUSH";
	case TTA::BOTH: return "BOTH";
	}
	return std::string();
}
