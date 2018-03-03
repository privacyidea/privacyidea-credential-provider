/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
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

#ifndef _PROVIDER_COMMON
#define _PROVIDER_COMMON
#pragma once

#include "guid.h"
#include "lang.h"
#include "resource.h"

#define MAX_NUM_FIELDS 10

#define MAX_ULONG  ((ULONG)(-1))

#define ZERO(NAME) \
	SecureZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME)

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define EMPTY(NAME) \
	(NAME == NULL || NAME[0] == NULL)

#include "scenarios.h"

#endif
