#include "hmac_sha1.h"

namespace HMAC_SHA1
{

	/* Powers of ten */
	static const int    powers10[] = { 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

	HRESULT ComputeHMACSHA1(unsigned char *key, int keysize, unsigned char *message, int messagesize, unsigned char *hmac)
	{
		HRESULT result = E_FAIL;

		//--------------------------------------------------------------------
		// Declare variables.
		//
		// hProv:           Handle to a cryptographic service provider (CSP). 
		//                  This example retrieves the default provider for  
		//                  the PROV_RSA_FULL provider type.  
		// hHash:           Handle to the hash object needed to create a hash.
		// hKey:            Handle to a symmetric key. This example creates a 
		//                  key for the RC4 algorithm.
		// hHmacHash:       Handle to an HMAC hash.
		// pbHash:          Pointer to the hash.
		// dwDataLen:       Length, in bytes, of the hash.
		// Data1:           Password string used to create a symmetric key.
		// Data2:           Message string to be hashed.
		// HmacInfo:        Instance of an HMAC_INFO structure that contains 
		//                  information about the HMAC hash.
		// 
		HCRYPTPROV  hProv = NULL;
		HCRYPTHASH  hHash = NULL;
		HCRYPTKEY   hKey = NULL;
		HCRYPTHASH  hHmacHash = NULL;
		PBYTE       pbHash = NULL;
		DWORD       dwDataLen = 0;
		//BYTE        Data1[] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };
		//BYTE        Data2[] = { 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 };
		HMAC_INFO   HmacInfo;

		unsigned char *Data1 = key;
		int Data1Size = keysize;

		unsigned char *Data2 = message;
		int Data2Size = messagesize;

		//--------------------------------------------------------------------
		// Zero the HMAC_INFO structure and use the SHA1 algorithm for
		// hashing.

		ZeroMemory(&HmacInfo, sizeof(HmacInfo));
		HmacInfo.HashAlgid = CALG_SHA1;

		//--------------------------------------------------------------------
		// Acquire a handle to the default RSA cryptographic service provider.

		if (!CryptAcquireContext(
			&hProv,                   // handle of the CSP
			NULL,                     // key container name
			NULL,                     // CSP name
			PROV_RSA_FULL,            // provider type
			CRYPT_VERIFYCONTEXT))     // no key access is requested
		{
			DebugPrintLn("Error in AcquireContext:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		//--------------------------------------------------------------------
		// Derive a symmetric key from a hash object by performing the
		// following steps:
		//    1. Call CryptCreateHash to retrieve a handle to a hash object.
		//    2. Call CryptHashData to add a text string (password) to the 
		//       hash object.
		//    3. Call CryptDeriveKey to create the symmetric key from the
		//       hashed password derived in step 2.
		// You will use the key later to create an HMAC hash object. 

		if (!CryptCreateHash(
			hProv,                    // handle of the CSP
			CALG_SHA1,                // hash algorithm to use
			0,                        // hash key
			0,                        // reserved
			&hHash))                  // address of hash object handle
		{
			DebugPrintLn("Error in CryptCreateHash:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		if (!CryptHashData(
			hHash,                    // handle of the hash object
			Data1,                    // password to hash
			Data1Size,				  // number of bytes of data to add
			0))                       // flags
		{
			DebugPrintLn("Error in CryptHashData:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		/*
		if (!CryptDeriveKey(
			hProv,                    // handle of the CSP
			CALG_RC4,                 // algorithm ID
			hHash,                    // handle to the hash object
			0,                        // flags
			&hKey))                   // address of the key handle
		{
			DebugPrintLn("Error in CryptDeriveKey:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}
		*/
		hKey = hHash;

		//--------------------------------------------------------------------
		// Create an HMAC by performing the following steps:
		//    1. Call CryptCreateHash to create a hash object and retrieve 
		//       a handle to it.
		//    2. Call CryptSetHashParam to set the instance of the HMAC_INFO 
		//       structure into the hash object.
		//    3. Call CryptHashData to compute a hash of the message.
		//    4. Call CryptGetHashParam to retrieve the size, in bytes, of
		//       the hash.
		//    5. Call malloc to allocate memory for the hash.
		//    6. Call CryptGetHashParam again to retrieve the HMAC hash.

		if (!CryptCreateHash(
			hProv,                    // handle of the CSP.
			CALG_HMAC,                // HMAC hash algorithm ID
			hKey,                     // key for the hash (see above)
			0,                        // reserved
			&hHmacHash))              // address of the hash handle
		{
			DebugPrintLn("Error in CryptCreateHash:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		if (!CryptSetHashParam(
			hHmacHash,                // handle of the HMAC hash object
			HP_HMAC_INFO,             // setting an HMAC_INFO object
			(BYTE*)&HmacInfo,         // the HMAC_INFO object
			0))                       // reserved
		{
			DebugPrintLn("Error in CryptSetHashParam:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		if (!CryptHashData(
			hHmacHash,                // handle of the HMAC hash object
			Data2,                    // message to hash
			Data2Size,				  // number of bytes of data to add
			0))                       // flags
		{
			DebugPrintLn("Error in CryptHashData:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		//--------------------------------------------------------------------
		// Call CryptGetHashParam twice. Call it the first time to retrieve
		// the size, in bytes, of the hash. Allocate memory. Then call 
		// CryptGetHashParam again to retrieve the hash value.

		if (!CryptGetHashParam(
			hHmacHash,                // handle of the HMAC hash object
			HP_HASHVAL,               // query on the hash value
			NULL,                     // filled on second call
			&dwDataLen,               // length, in bytes, of the hash
			0))
		{
			DebugPrintLn("Error in CryptGetHashParam:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		pbHash = (BYTE*)malloc(dwDataLen);
		if (NULL == pbHash)
		{
			DebugPrintLn("unable to allocate memory");
			goto ErrorExit;
		}

		if (!CryptGetHashParam(
			hHmacHash,                 // handle of the HMAC hash object
			HP_HASHVAL,                // query on the hash value
			pbHash,                    // pointer to the HMAC hash value
			&dwDataLen,                // length, in bytes, of the hash
			0))
		{
			DebugPrintLn("Error in CryptGetHashParam:");
			DebugPrintLn(GetLastError());
			goto ErrorExit;
		}

		// Print the hash to the console.
		/*
		DebugPrintLn("The hash is:");
		for (DWORD i = 0; i < dwDataLen; i++)
		{
		DebugPrintLn("%2.2x ", pbHash[i]);
		}
		*/
#ifdef _DEBUG
		INIT_ZERO_CHAR(hexstring, 256 + 1);
		const char hexDigits[] = { "0123456789abcdef" };

		for (int hashByte = 20; --hashByte >= 0;)
		{
			hexstring[hashByte << 1] = hexDigits[(pbHash[hashByte] >> 4) & 0xf];
			hexstring[(hashByte << 1) + 1] = hexDigits[pbHash[hashByte] & 0xf];
		}

		hexstring[256] = 0; // add terminating zero

		DebugPrintLn(hexstring);
#endif

		// Copy the hash to hmac

		for (DWORD i = 0; i < dwDataLen; i++)
		{
			hmac[i] = pbHash[i];
		}

		result = S_OK;

		// Free resources.
	ErrorExit:
		if (hHmacHash)
			CryptDestroyHash(hHmacHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (pbHash)
			free(pbHash);

		return result;
	}

	HRESULT TruncateHMACSHA1(unsigned char *hmac, int hmacsize, int truncatedlength, char *truncated, int truncatedsize)
	{
		const int max10 = sizeof(powers10) / sizeof(*powers10);

		int offset;
		int value;

		/* Extract selected bytes to get 32 bit integer value */
		offset = hmac[hmacsize - 1] & 0x0f;
		value = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
			  | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);

		/* Generate decimal digits */
		if (truncated != NULL) {
			_snprintf_s(truncated, truncatedsize, truncatedlength, "%0*d", truncatedlength < max10 ? truncatedlength : max10,
				truncatedlength < max10 ? value % powers10[truncatedlength - 1] : value);
		}

		return S_OK;
	}

}