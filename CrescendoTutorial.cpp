#include <Windows.h>
#include <ncrypt.h>

int main()
{
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE hKey;
	SECURITY_STATUS lRet;
	LPTSTR szPin = L"00000000";
	LPBYTE pbRawKey;
	DWORD  cbRawKey;
	LPBYTE pbSerial = NULL;
	DWORD  cbSerial = 0;
	DWORD  dwKeyLen = 2048;

	lRet = NCryptOpenStorageProvider(&hProv, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);

	// Retrieve serial number for the card
	lRet = NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, NULL, 0, &cbSerial, 0);
	pbSerial = (LPBYTE)malloc(cbSerial);
	lRet = NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, pbSerial, cbSerial, &cbSerial, 0);
	// Use the serial number and don't forget to free memory!
	free(pbSerial);

	lRet = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"Crescendo C1150 Key", AT_SIGNATURE, 0);

	// DWORDs are 4 bytes long
	lRet = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (LPBYTE)&dwKeyLen, 4, 0);
	// We can pass the pin and prevent the pin dialog to be displayed
	lRet = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
	lRet = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);

	lRet = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &cbRawKey, 0);
	pbRawKey = (LPBYTE)malloc(cbRawKey);
	lRet = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pbRawKey, cbRawKey, &cbRawKey, 0);
	// pbRawKey contains now the value of the public key that can be used to request a certificate
	// lRet = NCryptSetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCert, cbCert, 0);
	free(pbRawKey);
	lRet = NCryptFreeObject(hKey);

	// Now delete the key. We get a new handle to show how it would happen in a different session
	lRet = NCryptOpenKey(hProv, &hKey, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
	lRet = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
	lRet = NCryptDeleteKey(hKey, 0);  // After this, no need to free the key handle

	lRet = NCryptFreeObject(hProv);
}