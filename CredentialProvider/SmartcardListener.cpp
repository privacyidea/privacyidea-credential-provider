#include "SmartcardListener.h"
#include "Logger.h"

SmartcardListener::SmartcardListener()
{
	LONG res = SCARD_S_SUCCESS;
	res = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &_hContext);
	if (res == SCARD_S_SUCCESS)
	{
		LPTSTR mszReaders = NULL;
		LPTSTR pReader = NULL;
		DWORD pcchReaders = SCARD_AUTOALLOCATE;
		res = SCardListReaders(_hContext, NULL, (LPTSTR)&mszReaders, &pcchReaders);
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
				_readerStates.push_back(readerState);

				pReader = pReader + wcslen((wchar_t*)pReader) + 1;
			}
		}
		else
		{
			PIError("SCardListReaders: " + std::to_string(res));
			_hContext = NULL;
		}
	}
	else
	{
		PIError("SCardEstablishContext: " + std::to_string(res));
		_hContext = NULL;
	}
}

SmartcardListener::~SmartcardListener()
{
	if (_hContext != NULL)
	{
		SCardReleaseContext(_hContext);
	}
}

bool SmartcardListener::CheckForSmartcardPresence()
{
	if (_hContext != NULL)
	{
		LONG res = SCARD_S_SUCCESS;
		constexpr DWORD dwTimeout = 100;
		res = SCardGetStatusChange(_hContext, dwTimeout, _readerStates.data(), _readerStates.size());
		if (res == SCARD_S_SUCCESS)
		{
			for (auto& readerState : _readerStates)
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
	}
	return false;
}
