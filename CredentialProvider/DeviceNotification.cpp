/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024 NetKnights GmbH
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

#include "DeviceNotification.h"
#include "Logger.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbt.h>
#include <iostream>
#include <string>
#include <thread>

static const GUID g_hidGUID = { 0x4D1E55B2L, 0xF16F, 0x11CF, 0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30 };
static HWND g_hWnd = NULL;

std::atomic<bool> DeviceNotification::newDevices(false);
std::atomic<bool> stopPump(false);

void ErrorHandler(LPCTSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	const DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	PIError(std::wstring(lpszFunction) + L" failed with error " + std::to_wstring(dw) + L": " + (LPCTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
}

void MessagePump(HWND hWnd)
{
	MSG msg;
	int retVal;
	PIDebug("MessagePump start");
	while (stopPump == false)
	{
		retVal = PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
		if (retVal == -1)
		{
			ErrorHandler(L"GetMessage");
			break;
		}
		else
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	PIDebug("MessagePump stopped");
}

INT_PTR WINAPI WinProcCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRet = 1;
	static ULONGLONG msgCount = 0;
	static HDEVNOTIFY hDeviceNotify;

	switch (message)
	{
		case WM_CREATE:
		{
			PIDebug("WM_CREATE");
			DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;

			ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
			NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
			NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
			NotificationFilter.dbcc_classguid = g_hidGUID;

			hDeviceNotify = RegisterDeviceNotification(
				hWnd,                       // events recipient
				&NotificationFilter,        // type of device
				DEVICE_NOTIFY_WINDOW_HANDLE // type of recipient handle
			);

			if (NULL == hDeviceNotify)
			{
				ErrorHandler(L"RegisterDeviceNotification");
				return -1;
			}

			PIDebug("Registered for device notification...");
			break;
		}
		case WM_DEVICECHANGE:
		{
			PIDebug("WM_DEVICECHANGE");
			switch (wParam)
			{
				case DBT_DEVICEARRIVAL:
				{
					DeviceNotification::newDevices.store(true);
					break;
				}
				default:
				{
					break;
				}
			}
			break;
		}
		case WM_CLOSE:
		{
			PIDebug("WM_CLOSE");
			stopPump = true;
			if (!UnregisterDeviceNotification(hDeviceNotify))
			{
				ErrorHandler(L"UnregisterDeviceNotification");
				return -1;
			}
			DestroyWindow(hWnd);
			g_hWnd = NULL;
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			break;
		}
		default:
		{
			// Send all other messages on to the default windows handler.
			lRet = DefWindowProc(hWnd, message, wParam, lParam);
			break;
		}
	}

	return lRet;
}

int TaskRegister()
{
	// Register the window class with the WinProcCallback as the message handler
	static const wchar_t* className = L"PI_MESSAGE_WINDOW";
	WNDCLASSEX wx = {};
	wx.cbSize = sizeof(WNDCLASSEX);
	wx.lpfnWndProc = reinterpret_cast<WNDPROC>(WinProcCallback);
	wx.hInstance = reinterpret_cast<HINSTANCE>(GetModuleHandle(0));
	wx.lpszClassName = className;

	if (!RegisterClassEx(&wx))
	{
		PIDebug("Failed to register window class");
		return -1;
	}

	// Upon creation of the window, a WM_CREATE message will be sent to the WinProcCallback, which will 
	// trigger the code to register the window for device notifications
	g_hWnd = CreateWindowEx(0, className, L"theWindow", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);

	if (!g_hWnd)
	{
		PIDebug("Failed to create window");
		return -1;
	}

	MessagePump(g_hWnd);

	return 0;
}

int DeviceNotification::Register()
{
	PIDebug("DeviceNotification::Register");
	std::thread t(TaskRegister);
	t.detach();
	return 0;
}

int DeviceNotification::Unregister()
{
	PIDebug("DeviceNotification::Unregister");
	if (g_hWnd != NULL)
	{
		SendMessage(g_hWnd, WM_CLOSE, 0, 0);
	}
	return 0;
}
