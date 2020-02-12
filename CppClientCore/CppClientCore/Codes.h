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
#pragma once

#define PI_AUTH_SUCCESS								((HRESULT)0x78809001)
#define PI_AUTH_FAILURE								((HRESULT)0x78809002)
#define PI_AUTH_ERROR								((HRESULT)0x78809003)
#define PI_TRANSACTION_SUCCESS						((HRESULT)0x78809004)
#define PI_TRANSACTION_FAILURE						((HRESULT)0x78809005)
#define PI_OFFLINE_OTP_SUCCESS						((HRESULT)0x78809006)
#define PI_OFFLINE_OTP_FAILURE						((HRESULT)0x78809007)
#define PI_TRIGGERED_CHALLENGE						((HRESULT)0x78809008)
#define PI_NO_CHALLENGES							((HRESULT)0x78809009)

#define PI_ERROR_EMPTY_RESPONSE						((HRESULT)0x7880900E)
#define PI_STATUS_NOT_SET							((HRESULT)0x7880900F)

#define PI_OFFLINE_DATA_NO_OTPS_LEFT				((HRESULT)0x88809020)
#define PI_OFFLINE_DATA_USER_NOT_FOUND				((HRESULT)0x88809021)
#define PI_OFFLINE_NO_OFFLINE_DATA					((HRESULT)0x88809022) 
#define PI_OFFLINE_FILE_DOES_NOT_EXIST				((HRESULT)0x88809023) // Not an error
#define PI_OFFLINE_FILE_EMPTY						((HRESULT)0x88809024)

#define PI_JSON_FORMAT_ERROR						((HRESULT)0x88809030)
#define PI_JSON_PARSE_ERROR							((HRESULT)0x88809031)
#define PI_JSON_ERROR_CONTAINED						((HRESULT)0x78809032)
