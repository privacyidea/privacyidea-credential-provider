#pragma once
#include <winscard.h>
#include <vector>

class SmartcardListener
{
public:
	/// <summary>
	/// Creates a SCARDCONTEXT and gets all connected readers. These readers will be checked when
	/// calling CheckForSmartcardPresence. If the readers change, the object has to be recreated to use them.
	/// </summary>
	SmartcardListener();
	
	/// <summary>
	/// Releases the SCARDCONTEXT.
	/// </summary>
	~SmartcardListener();

	/// <summary>
	/// Does SCardGetStatusChange for SCARD_STATE_PRESENT once.
	/// </summary>
	/// <returns>true or false</returns>
	int CheckForSmartcardPresence();

private:
	SCARDCONTEXT hContext = NULL;
	std::vector<SCARD_READERSTATE> readerStates;
};

