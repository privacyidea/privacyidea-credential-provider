/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**
** Author		Dominik Pretzsch
**				Nils Behlen
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
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef _FIELD_INITIALIZOR
#define _FIELD_INITIALIZOR
#pragma once

enum FIELD_INITIALIZOR_TYPE
{
	FIT_NONE = 0,
	FIT_VALUE = 1,
	FIT_USERNAME = 2,
	FIT_USERNAME_AND_DOMAIN = 3,
	FIT_LOGIN_TEXT = 4,
	FIT_VALUE_OR_LOCKED_TEXT = 5,
	FIT_VALUE_OR_LOGIN_TEXT = 6,
};

struct FIELD_INITIALIZOR
{
	FIELD_INITIALIZOR_TYPE type;
	wchar_t* value;
};

#endif