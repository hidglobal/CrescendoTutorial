#include <Windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "cardmod.h"

typedef DWORD(WINAPI *PACQUIRECONTEXT)(PCARD_DATA, DWORD);

HANDLE			hHeap = NULL;

void CheckResult(const char* functionName, LONG lRet)
{
	if (lRet != SCARD_S_SUCCESS)
	{
		fprintf(stderr, "%s error 0x%08lX\n", functionName, (unsigned long)lRet);
		exit(EXIT_FAILURE);
	}
}

LPVOID WINAPI CspAlloc(SIZE_T Size)
{
	return HeapAlloc(hHeap, 0, Size);
}

LPVOID WINAPI CspReAlloc(LPVOID Address, SIZE_T Size)
{
	return HeapReAlloc(hHeap, 0, Address, Size);
}

void WINAPI CspFree(LPVOID Address)
{
	if (Address)
	{
		HeapFree(hHeap, 0, Address);
	}
}

LONG DesResponse(LPBYTE pbData, DWORD cbData)
{
	DWORD lRet = SCARD_S_SUCCESS;
	HCRYPTPROV hProv = 0;
	DWORD dwMode = CRYPT_MODE_ECB;
	BYTE *pbLocData = NULL;
	DWORD cbLocData = 8, count = 0;
	HCRYPTKEY hKey = 0;

	BYTE DesKeyBlob[] = {
		0x08, 0x02, 0x00, 0x00, 0x03, 0x66, 0x00, 0x00,
		0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	pbLocData = (BYTE *)malloc(sizeof(BYTE)*cbLocData);
	memcpy(pbLocData, pbData, cbLocData);

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptImportKey(
		hProv,
		DesKeyBlob,
		sizeof(DesKeyBlob),
		0,
		0,
		&hKey))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptSetKeyParam(
		hKey,
		KP_MODE,
		(BYTE *)&dwMode,
		0))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptEncrypt(
		hKey,
		0,
		FALSE,
		0,
		pbLocData,
		&cbLocData,
		cbLocData))
	{
		lRet = GetLastError();
		goto Cleanup;
	}

	memcpy(pbData, pbLocData, cbLocData);

Cleanup:
	if (hKey)
	{
		CryptDestroyKey(hKey);
		hKey = 0;
	}
	if (pbLocData)
	{
		free(pbLocData);
		pbLocData = NULL;
	}
	if (hProv)
		CryptReleaseContext(hProv, 0);

	return lRet;
}

LONG AesResponse(LPBYTE pbData, DWORD cbData)
{
	DWORD lRet = SCARD_S_SUCCESS;
	HCRYPTPROV hProv = 0;
	DWORD dwMode = CRYPT_MODE_CBC;
	BYTE* pbLocData = NULL;
	DWORD cbLocData = 16, count = 0;
	HCRYPTKEY hKey = 0;

	BYTE AesKeyBlob[] = {
		0x08, 0x02, 0x00, 0x00, 0x0E, 0x66, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	pbLocData = (BYTE*)malloc(sizeof(BYTE) * cbLocData);
	memcpy(pbLocData, pbData, cbLocData);

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		MS_ENH_RSA_AES_PROV,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptImportKey(
		hProv,
		AesKeyBlob,
		sizeof(AesKeyBlob),
		0,
		0,
		&hKey))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptSetKeyParam(
		hKey,
		KP_MODE,
		(BYTE*)&dwMode,
		0))
	{
		lRet = GetLastError();
		goto Cleanup;
	}
	if (!CryptEncrypt(
		hKey,
		0,
		FALSE,
		0,
		pbLocData,
		&cbLocData,
		cbLocData))
	{
		lRet = GetLastError();
		goto Cleanup;
	}

	memcpy(pbData, pbLocData, cbLocData);

Cleanup:
	if (hKey)
	{
		CryptDestroyKey(hKey);
		hKey = 0;
	}
	if (pbLocData)
	{
		free(pbLocData);
		pbLocData = NULL;
	}
	if (hProv)
		CryptReleaseContext(hProv, 0);

	return lRet;
}

int main()
{
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE  hKey;
	SECURITY_STATUS    lRet;
	LPTSTR             szPin = L"00000000";
	LPBYTE             pbRawKey;
	DWORD              cbRawKey;
	LPBYTE             pbSerial = NULL;
	DWORD              cbSerial = 0;
	DWORD              dwKeyLen = 2048;

	SCARDCONTEXT       hContext = 0;
	BYTE               pbAtr[36];
	DWORD              cbAtr = 36;
	LPTSTR             szCards = NULL;
	DWORD              cchCards = 0;
	LPTSTR             szProvider = NULL;
	DWORD              cchProvider = 0;
	HMODULE            hDriver = NULL;
	DWORD              dwAP = 0;
	PACQUIRECONTEXT    pCardAcquireContext = NULL;
	CARD_DATA          cardData;
	LPBYTE             ppbChallenge;
	DWORD              cbChallenge;
	DWORD              cbRemaining = 0;

	/*
	 * For PIN management functions, we go through the minidriver
	 */
	hHeap = HeapCreate(0, 0x00010000, 0x0010000);

	lRet = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
	CheckResult("SCardEstablishContext", lRet);

	LPOPENCARDNAME_EXW ocn = new OPENCARDNAME_EXW();
	ocn->dwFlags = SC_DLG_MINIMAL_UI;
	ocn->hSCardContext = hContext;
	ocn->dwShareMode = SCARD_SHARE_SHARED;
	ocn->dwPreferredProtocols = SCARD_PROTOCOL_Tx;
	ocn->lpstrRdr = (LPWSTR)malloc(sizeof(wchar_t) * 255);
	ocn->nMaxRdr = 255;
	ocn->lpstrCard = (LPWSTR)malloc(sizeof(wchar_t) * 255);
	ocn->nMaxCard = 255;
	ocn->dwStructSize = sizeof(OPENCARDNAME_EXW);
	lRet = SCardUIDlgSelectCard(ocn);
	CheckResult("SCardUIDlgSelectCard", lRet);

	lRet = SCardGetAttrib(ocn->hCardHandle, SCARD_ATTR_ATR_STRING, pbAtr, &cbAtr);
	CheckResult("SCardGetAttrib", lRet);
	lRet = SCardListCards(hContext, pbAtr, NULL, 0, NULL, &cchCards);
	CheckResult("SCardListCards", lRet);
	szCards = (LPTSTR)CspAlloc(cchCards * sizeof(TCHAR));
	lRet = SCardListCards(hContext, pbAtr, NULL, 0, szCards, &cchCards);
	CheckResult("SCardListCards", lRet);

	lRet = SCardGetCardTypeProviderName(hContext, szCards, 0x80000001, NULL, &cchProvider);
	CheckResult("SCardGetCardTypeProviderName", lRet);
	szProvider = (LPTSTR)CspAlloc(cchProvider * sizeof(TCHAR));
	lRet = SCardGetCardTypeProviderName(hContext, szCards, 0x80000001, szProvider, &cchProvider);
	CheckResult("SCardGetCardTypeProviderName", lRet);

	hDriver = LoadLibrary(szProvider);

	lRet = SCardBeginTransaction(ocn->hCardHandle);
	CheckResult("SCardBeginTransaction", lRet);

	pCardAcquireContext = (PACQUIRECONTEXT)GetProcAddress(hDriver, "CardAcquireContext");

	memset(&cardData, 0, sizeof(CARD_DATA));
	cardData.dwVersion = CARD_DATA_CURRENT_VERSION;
	cardData.pbAtr = pbAtr;
	cardData.cbAtr = cbAtr;
	cardData.pwszCardName = szCards;

	// Memory management functions
	cardData.pfnCspAlloc = (PFN_CSP_ALLOC)CspAlloc;
	cardData.pfnCspReAlloc = (PFN_CSP_REALLOC)CspReAlloc;
	cardData.pfnCspFree = (PFN_CSP_FREE)CspFree;

	cardData.hSCardCtx = hContext;
	cardData.hScard = ocn->hCardHandle;

	lRet = (pCardAcquireContext)(&cardData, 0);
	CheckResult("CardAcquireContext", lRet);

	// Verify User PIN
	BYTE   pbPin[] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
	DWORD  cbPin = 6;
	lRet = (cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, pbPin, cbPin, &cbRemaining);
	CheckResult("CardAuthenticatePin", lRet);

	// Change User PIN
	BYTE   pbNewPin[] = { 0x31, 0x31, 0x32, 0x32, 0x33, 0x33 };
	DWORD  cbNewPin = 6;
	//lRet = (cardData.pfnCardChangeAuthenticator)(&cardData, wszCARD_USER_USER, pbPin, cbPin, pbNewPin, cbNewPin, 0, PIN_CHANGE_FLAG_CHANGEPIN, &cbRemaining);

	// Challenge / response authentication
	lRet = (cardData.pfnCardGetChallenge)(&cardData, &ppbChallenge, &cbChallenge);
	CheckResult("CardGetChallenge", lRet);
	if (cbChallenge == 8) {
		lRet = DesResponse(ppbChallenge, cbChallenge);
		CheckResult("DesResponse", lRet);
	}
	else {
		lRet = AesResponse(ppbChallenge, cbChallenge);
		CheckResult("AesResponse", lRet);
	}
	lRet = (cardData.pfnCardAuthenticateChallenge)(&cardData, ppbChallenge, cbChallenge, &cbRemaining);
	CheckResult("CardAuthenticateChallenge", lRet);
	(cardData.pfnCspFree)(ppbChallenge);

	// Change administration key
	lRet = (cardData.pfnCardGetChallenge)(&cardData, &ppbChallenge, &cbChallenge);
	CheckResult("CardGetChallenge", lRet);
	BYTE  pbNewKey[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DWORD cbNewKey = 24;
	if (cbChallenge == 8) {
		lRet = DesResponse(ppbChallenge, cbChallenge);
		CheckResult("DesResponse", lRet);
		cbNewKey = 16;
	}
	else {
		lRet = AesResponse(ppbChallenge, cbChallenge);
		CheckResult("AesResponse", lRet);
		cbNewKey = 16;
	}
	lRet = (cardData.pfnCardChangeAuthenticator)(&cardData, wszCARD_USER_ADMIN, ppbChallenge, cbChallenge, pbNewKey, cbNewKey, 0, CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE, &cbRemaining);
	CheckResult("CardChangeAuthenticator", lRet);
	(cardData.pfnCspFree)(ppbChallenge);
	
	// Unblock User PIN
	lRet = (cardData.pfnCardGetChallenge)(&cardData, &ppbChallenge, &cbChallenge);
	CheckResult("CardGetChallenge", lRet);
	if (cbChallenge == 8) {
		lRet = DesResponse(ppbChallenge, cbChallenge);
		CheckResult("DesResponse", lRet);
	}
	else {
		lRet = AesResponse(ppbChallenge, cbChallenge);
		CheckResult("AesResponse", lRet);
	}
	lRet = (cardData.pfnCardChangeAuthenticatorEx)(&cardData, PIN_CHANGE_FLAG_UNBLOCK, ROLE_ADMIN, ppbChallenge, cbChallenge, ROLE_USER, pbNewPin, cbNewPin, 0, &cbRemaining);
	CheckResult("CardChangeAuthenticatorEx", lRet);
	(cardData.pfnCspFree)(ppbChallenge);

	lRet = (cardData.pfnCardDeleteContext)(&cardData);
	CheckResult("CardDeleteContext", lRet);
	lRet = SCardEndTransaction(ocn->hCardHandle, SCARD_LEAVE_CARD);
	CheckResult("SCardEndTransaction", lRet);
	lRet = SCardDisconnect(ocn->hCardHandle, SCARD_LEAVE_CARD);
	CheckResult("SCardDisconnect", lRet);
	FreeLibrary(hDriver);
	CspFree(szProvider);
	CspFree(szCards);
	HeapDestroy(hHeap);

	/*
	 * For cryptographic key management and use, we go through CNG
	 */
	lRet = NCryptOpenStorageProvider(&hProv, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
	CheckResult("NCryptOpenStorageProvider", lRet);

	// Retrieve serial number for the card
	lRet = NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, NULL, 0, &cbSerial, 0);
	CheckResult("NCryptGetProperty", lRet);
	pbSerial = (LPBYTE)malloc(cbSerial);
	lRet = NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, pbSerial, cbSerial, &cbSerial, 0);
	CheckResult("NCryptGetProperty", lRet);
	// Use the serial number and don't forget to free memory!
	free(pbSerial);

	lRet = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
	CheckResult("NCryptCreatePersistedKey", lRet);

	// DWORDs are 4 bytes long
	lRet = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (LPBYTE)&dwKeyLen, 4, 0);
	CheckResult("NCryptSetProperty", lRet);
	// We can pass the pin and prevent the pin dialog to be displayed
	lRet = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
	CheckResult("NCryptSetProperty", lRet);
	lRet = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);
	CheckResult("NCryptFinalizeKey", lRet);

	lRet = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &cbRawKey, 0);
	CheckResult("NCryptExportKey", lRet);
	pbRawKey = (LPBYTE)malloc(cbRawKey);
	lRet = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pbRawKey, cbRawKey, &cbRawKey, 0);
	CheckResult("NCryptExportKey", lRet);
	// pbRawKey contains now the value of the public key that can be used to request a certificate
	// lRet = NCryptSetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCert, cbCert, 0);
	free(pbRawKey);
	lRet = NCryptFreeObject(hKey);
	CheckResult("NCryptFreeObject", lRet);

	// Now delete the key. We get a new handle to show how it would happen in a different session
	lRet = NCryptOpenKey(hProv, &hKey, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
	CheckResult("NCryptOpenKey", lRet);
	lRet = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
	CheckResult("NCryptSetProperty", lRet);
	lRet = NCryptDeleteKey(hKey, 0);  // After this, no need to free the key handle
	CheckResult("NCryptDeleteKey", lRet);

	lRet = NCryptFreeObject(hProv);
	CheckResult("NCryptFreeObject", lRet);

	return EXIT_SUCCESS;
}