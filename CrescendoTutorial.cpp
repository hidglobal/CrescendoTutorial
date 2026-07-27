#include <Windows.h>
#include <bcrypt.h>
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

const char* PinIdToLabel(DWORD pinId)
{
	switch (pinId)
	{
	case ROLE_USER:
		return "ROLE_USER";
	case ROLE_ADMIN:
		return "ROLE_ADMIN";
	default:
		break;
	}

	static char labels[MAX_PINS][8];
	if (pinId < MAX_PINS)
	{
		sprintf_s(labels[pinId], sizeof(labels[pinId]), "%lu", (unsigned long)pinId);
		return labels[pinId];
	}

	return "Unknown";
}

const char* SecretTypeToString(SECRET_TYPE secretType)
{
	switch (secretType)
	{
	case AlphaNumericPinType:
		return "AlphaNumericPinType";
	case ExternalPinType:
		return "ExternalPinType";
	case ChallengeResponsePinType:
		return "ChallengeResponsePinType";
	case EmptyPinType:
		return "EmptyPinType";
	default:
		return "UnknownSecretType";
	}
}

const char* SecretPurposeToString(SECRET_PURPOSE secretPurpose)
{
	switch (secretPurpose)
	{
	case AuthenticationPin:
		return "AuthenticationPin";
	case DigitalSignaturePin:
		return "DigitalSignaturePin";
	case EncryptionPin:
		return "EncryptionPin";
	case NonRepudiationPin:
		return "NonRepudiationPin";
	case AdministratorPin:
		return "AdministratorPin";
	case PrimaryCardPin:
		return "PrimaryCardPin";
	case UnblockOnlyPin:
		return "UnblockOnlyPin";
	default:
		return "UnknownSecretPurpose";
	}
}

void FormatPinSet(PIN_SET pinSet, char* output, size_t outputSize)
{
	bool first = true;

	if (!output || outputSize == 0)
	{
		return;
	}

	output[0] = '\0';
	for (DWORD i = 0; i < MAX_PINS; i++)
	{
		if (!IS_PIN_SET(pinSet, i))
		{
			continue;
		}

		if (!first)
		{
			strcat_s(output, outputSize, ",");
		}
		strcat_s(output, outputSize, PinIdToLabel(i));
		first = false;
	}

	if (first)
	{
		strcpy_s(output, outputSize, "None");
	}
}

void PrintPinInfo(int pinId, const PIN_INFO* pinInfo)
{
	char changePermission[128] = { 0 };
	char unblockPermission[128] = { 0 };
	static bool headerPrinted = false;

	if (!pinInfo)
	{
		return;
	}

	FormatPinSet(pinInfo->dwChangePermission, changePermission, sizeof(changePermission));
	FormatPinSet(pinInfo->dwUnblockPermission, unblockPermission, sizeof(unblockPermission));

	if (!headerPrinted)
	{
		printf("\n%-12s %-28s %-24s %-32s %-32s\n",
			"PIN",
			"Secret Type",
			"Secret Purpose",
			"Change Permission",
			"Unblock Permission");
		printf("%-12s %-28s %-24s %-32s %-32s\n",
			"------------",
			"----------------------------",
			"------------------------",
			"--------------------------------",
			"--------------------------------");
		headerPrinted = true;
	}

	printf("%-12s %-28s %-24s %-32s %-32s\n",
		PinIdToLabel((DWORD)pinId),
		SecretTypeToString(pinInfo->PinType),
		SecretPurposeToString(pinInfo->PinPurpose),
		changePermission,
		unblockPermission);
}

LONG SymmetricChallengeResponse(
	LPBYTE pbData,
	DWORD cbData,
	LPCWSTR pszAlgorithm,
	const BYTE* pbKey,
	DWORD cbKey,
	LPCWSTR pszChainingMode,
	const BYTE* pbIv,
	DWORD cbIv);

LONG DesResponse(LPBYTE pbData, DWORD cbData)
{
	const BYTE desKey[24] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	return SymmetricChallengeResponse(
		pbData,
		cbData,
		BCRYPT_3DES_ALGORITHM,
		desKey,
		(DWORD)sizeof(desKey),
		BCRYPT_CHAIN_MODE_ECB,
		NULL,
		0);
}

LONG SymmetricChallengeResponse(
	LPBYTE pbData,
	DWORD cbData,
	LPCWSTR pszAlgorithm,
	const BYTE* pbKey,
	DWORD cbKey,
	LPCWSTR pszChainingMode,
	const BYTE* pbIv,
	DWORD cbIv)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE pbKeyObject = NULL;
	PBYTE pbLocData = NULL;
	PBYTE pbIvLocal = NULL;
	DWORD cbKeyObject = 0;
	DWORD cbResult = 0;
	NTSTATUS status = 0;
	DWORD cbChainingMode = 0;

	if (!pbData || cbData == 0 || !pszAlgorithm || !pbKey || cbKey == 0 || !pszChainingMode)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if ((pbIv && cbIv == 0) || (!pbIv && cbIv != 0))
	{
		return ERROR_INVALID_PARAMETER;
	}

	pbLocData = (PBYTE)malloc(cbData);
	if (!pbLocData)
	{
		return ERROR_OUTOFMEMORY;
	}
	memcpy(pbLocData, pbData, cbData);

	if (pbIv && cbIv)
	{
		pbIvLocal = (PBYTE)malloc(cbIv);
		if (!pbIvLocal)
		{
			status = ERROR_OUTOFMEMORY;
			goto Cleanup;
		}
		memcpy(pbIvLocal, pbIv, cbIv);
	}

	status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgorithm, NULL, 0);
	if (status < 0)
	{
		goto Cleanup;
	}

	cbChainingMode = ((DWORD)lstrlenW(pszChainingMode) + 1) * sizeof(WCHAR);
	status = BCryptSetProperty(
		hAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)pszChainingMode,
		cbChainingMode,
		0);
	if (status < 0)
	{
		goto Cleanup;
	}

	status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbKeyObject,
		sizeof(cbKeyObject),
		&cbResult,
		0);
	if (status < 0)
	{
		goto Cleanup;
	}

	pbKeyObject = (PBYTE)malloc(cbKeyObject);
	if (!pbKeyObject)
	{
		status = ERROR_OUTOFMEMORY;
		goto Cleanup;
	}

	status = BCryptGenerateSymmetricKey(
		hAlg,
		&hKey,
		pbKeyObject,
		cbKeyObject,
		(PBYTE)pbKey,
		cbKey,
		0);
	if (status < 0)
	{
		goto Cleanup;
	}

	status = BCryptEncrypt(
		hKey,
		pbLocData,
		cbData,
		NULL,
		pbIvLocal,
		cbIv,
		pbLocData,
		cbData,
		&cbResult,
		0);
	if (status < 0)
	{
		goto Cleanup;
	}

	if (cbResult != cbData)
	{
		status = ERROR_INVALID_DATA;
		goto Cleanup;
	}

	memcpy(pbData, pbLocData, cbData);

Cleanup:
	if (hKey)
	{
		BCryptDestroyKey(hKey);
	}
	if (pbKeyObject)
	{
		free(pbKeyObject);
	}
	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	if (pbIvLocal)
	{
		free(pbIvLocal);
	}
	if (pbLocData)
	{
		free(pbLocData);
	}

	return status;
}

LONG AesResponse(LPBYTE pbData, DWORD cbData)
{
	const BYTE aesKey[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	BYTE iv[16] = { 0 };

	return SymmetricChallengeResponse(
		pbData,
		cbData,
		BCRYPT_AES_ALGORITHM,
		aesKey,
		(DWORD)sizeof(aesKey),
		BCRYPT_CHAIN_MODE_CBC,
		iv,
		(DWORD)sizeof(iv));
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
	BYTE   pbPin[] = { 0x34, 0x30, 0x34, 0x31, 0x34, 0x32, 0x34, 0x33 };
	DWORD  cbPin = 8;
	lRet = (cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, pbPin, cbPin, &cbRemaining);
	CheckResult("CardAuthenticatePin", lRet);

	// Change User PIN
	BYTE   pbNewPin[] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
	DWORD  cbNewPin = 8;
	lRet = (cardData.pfnCardChangeAuthenticatorEx)(&cardData, PIN_CHANGE_FLAG_CHANGEPIN, ROLE_USER, pbPin, cbPin, ROLE_USER, pbNewPin, cbNewPin, 0, &cbRemaining);
	//lRet = (cardData.pfnCardChangeAuthenticator)(&cardData, wszCARD_USER_USER, pbPin, cbPin, pbNewPin, cbNewPin, 0, PIN_CHANGE_FLAG_CHANGEPIN, &cbRemaining);
	CheckResult("CardChangeAuthenticatorEx", lRet);

	BYTE  pbNewKey[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DWORD cbNewKey = 16;
	lRet = (cardData.pfnCardChangeAuthenticatorEx)(&cardData, PIN_CHANGE_FLAG_UNBLOCK, ROLE_USER, pbNewPin, cbNewPin, ROLE_ADMIN, pbNewKey, cbNewKey, 0, &cbRemaining);
	CheckResult("CardChangeAuthenticatorEx", lRet);
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

	// Retrieve PIN properties
	PIN_SET pinSet;
	DWORD dwDataLen = 0;
	lRet = (cardData.pfnCardGetProperty)(&cardData, CP_CARD_LIST_PINS, (LPBYTE)&pinSet, sizeof(pinSet), &dwDataLen, 0);
	CheckResult("CardGetProperty (PIN_SET)", lRet);
	for (int i = 0; i < 8; i++) {
		if (IS_PIN_SET(pinSet, i)) {
			PIN_INFO pinInfo;
			pinInfo.dwVersion = PIN_INFO_CURRENT_VERSION;
			dwDataLen = sizeof(pinInfo);
			lRet = (cardData.pfnCardGetProperty)(&cardData, CP_CARD_PIN_INFO, (LPBYTE)&pinInfo, sizeof(pinInfo), &dwDataLen, i);
			CheckResult("CardGetProperty (PIN_INFO)", lRet);
			PrintPinInfo(i, &pinInfo);
		}
	}

	lRet = (cardData.pfnCardDeleteContext)(&cardData);
	CheckResult("CardDeleteContext", lRet);
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

	lRet = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"Crescendo 4000 Key", AT_SIGNATURE, 0);
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
	lRet = NCryptOpenKey(hProv, &hKey, L"Crescendo 4000 Key", AT_SIGNATURE, 0);
	CheckResult("NCryptOpenKey", lRet);
	lRet = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
	CheckResult("NCryptSetProperty", lRet);
	lRet = NCryptDeleteKey(hKey, 0);  // After this, no need to free the key handle
	CheckResult("NCryptDeleteKey", lRet);

	lRet = NCryptFreeObject(hProv);
	CheckResult("NCryptFreeObject", lRet);

	return EXIT_SUCCESS;
}