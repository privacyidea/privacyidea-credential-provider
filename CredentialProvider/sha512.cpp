#include "sha512.h"

namespace sha512
{
	// hash will need 64-bytes
	void calc(const void* src, const int bytelength, unsigned char *&hash)
	{
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		//BYTE *pbHash = NULL;
		DWORD dwHashLen;

		DWORD dwCount;

		// Cast the void src pointer to be the byte array we can work with.
		const unsigned char* pbBuffer = (const unsigned char*)src;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			DebugPrintLn(GetLastError());
			return;
		}
		if (!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash)) {
			DebugPrintLn(GetLastError());
			return;
		}

		if (!CryptHashData(hHash, pbBuffer, bytelength, 0)) {
			DebugPrintLn(GetLastError());
			return;
		}

		dwCount = sizeof(DWORD);
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&dwHashLen, &dwCount, 0)) {
			DebugPrintLn(GetLastError());
			return;
		}
		//if ((pbHash = (unsigned char*)malloc(dwHashLen)) == NULL) {
		if ((hash = (unsigned char*)malloc(dwHashLen)) == NULL) {
			return;
		}

		//memset(pbHash, 0, dwHashLen);
		memset(hash, 0, dwHashLen);

		//if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
		if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &dwHashLen, 0)) {
			DebugPrintLn(GetLastError());
			return;
		}

		//unsigned INIT_ZERO_CHAR(hashBuffer, SHA512_HASH_LEN);

		// Store hash in result pointer, and make sure we get in in the correct order on both endian models.
		/*
		for (int hashByte = SHA512_HASH_LEN; --hashByte >= 0;)
		{
			//hashBuffer[hashByte] = (pbHash[hashByte >> 2] >> (((3 - hashByte) & 0x3) << 3)) & 0xff;
			hashBuffer[hashByte] = pbHash[hashByte];
		}
		*/

		//hash = hashBuffer;

		if (hHash) CryptDestroyHash(hHash);
		if (hProv) CryptReleaseContext(hProv, 0);
	}

	void toHexString(const unsigned char* hash, char* hexstring)
	{
		const char hexDigits[] = { "0123456789abcdef" };

		for (int hashByte = SHA512_HASH_LEN; --hashByte >= 0;)
		{
			hexstring[hashByte << 1] = hexDigits[(hash[hashByte] >> 4) & 0xf];
			hexstring[(hashByte << 1) + 1] = hexDigits[hash[hashByte] & 0xf];
		}

		hexstring[2 * SHA512_HASH_LEN] = 0; // add terminating zero
	}

}