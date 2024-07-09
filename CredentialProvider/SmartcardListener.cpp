#include "SmartcardListener.h"
#include "Logger.h"

SmartcardListener::SmartcardListener()
{
	LONG res = SCARD_S_SUCCESS;
	res = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
	if (res == SCARD_S_SUCCESS)
	{
		LPTSTR mszReaders = NULL;
		LPTSTR pReader = NULL;
		DWORD pcchReaders = SCARD_AUTOALLOCATE;
		res = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &pcchReaders);
		if (res == SCARD_S_SUCCESS)
		{
			pReader = mszReaders;
			
			while (pReader != nullptr && '\0' != *pReader)
			{
				PIDebug(L"Listening for smartcard on reader: " + std::wstring((wchar_t*)pReader, wcslen((wchar_t*)pReader)));
				SCARD_READERSTATE readerState{};
				readerState.szReader = pReader;
				readerState.pvUserData = NULL;
				readerState.dwCurrentState = NULL;
				readerState.dwEventState = NULL;
				readerState.cbAtr = NULL;
				readerStates.push_back(readerState);

				pReader = pReader + wcslen((wchar_t*)pReader) + 1;
			}
		}
		else
		{
			PIError("SCardListReaders: " + std::to_string(res));
		}
	}
	else
	{
		PIError("SCardEstablishContext: " + std::to_string(res));
	}
}

SmartcardListener::~SmartcardListener()
{
	if (hContext != NULL)
	{
		SCardReleaseContext(hContext);
	}
}

int SmartcardListener::CheckForSmartcardPresence()
{
	LONG res = SCARD_S_SUCCESS;
	const DWORD dwTimeout = 100;
	res = SCardGetStatusChange(hContext, dwTimeout, readerStates.data(), readerStates.size());
	if (res == SCARD_S_SUCCESS)
	{
		for (auto& readerState : readerStates)
		{
			if (readerState.dwEventState & SCARD_STATE_PRESENT)
			{
				return true;
			}
		}
	}
	else
	{
		PIError("SCardGetStatusChange: " + std::to_string(res));
	}
	return false;
}
