# Crescendo Minidriver Tutorial

HID Crescendo&reg; [smart cards](https://www.hidglobal.com/products/crescendo) and [security keys](https://www.hidglobal.com/products/crescendo-key) are natively supported in Windows, macOS or any operating system that supports PIV smart cards. This native support allows _using_ the certificates in the card. There are multiple tools available for Loading certificates and managing the card PIN:
- The [Crescendo Manager](https://www.hidglobal.com/drivers/48993) tool for individual cards
- The [Crescendo SDK](https://www.hidglobal.com/drivers/47439) for building applications that support the full range of device capabilities including FIDO2 and OATH.
- The [HID Credential Management System](https://www.hidglobal.com/products/hid-credential-management-system) for an enterprise-grade management application.
- The [Crescendo Minidriver](https://www.hidglobal.com/drivers/47444) for Windows tools using the Cryptography API.

## Crescendo Card Issuance

The Windows [Cryptogpraphic API: Next Generation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) provides a low level API to manage key material and certificates in _key storage providers_ that include smart cards when strong protection or portability of key material are important attributes of the desired solution. Smart cards typically protect access to private keys with a user PIN and the Windows [Smart Card Minidriver API](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secsmart/smart-card-api-reference) provides entry points for managing the contents of the card including managing the PIN.

The example application in this repository shows the basic sequence typical of card issuance using those Windows APIs. The high level process includes:

1. Connect to the smart card.
```
    NCryptOpenStorageProvider(&hProv, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
```

2. If needed, retrieve the unique card serial number
```
    NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, pbSerial, cbSerial, &cbSerial, 0);
```

3. Create a new persisted key, setting the desired length. It is possible to programatically pass the value of the card PIN and request the operation to be silent so no user interface is displayed. Alternatively, if the PIN is not passed Windows will display a dialog box prompting the user to enter the smart card PIN value. The default PIN of Crescendo smart cards is '00000000'.
```
    NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
    NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (LPBYTE)&dwKeyLen, 4, 0);
    NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
    NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);
```

4. Keys are generated and used in the trusted execution environment provided by the smart card. The public key can be exported in order to create a certificate request and submit it to a certification authoritiy. The certificate can be then added to the keypair.
```
    NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pbRawKey, cbRawKey, &cbRawKey, 0);
    NCryptSetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCert, cbCert, 0);
```

5. Keys (and their associated certificates) can also be deleted from the smart card. Again, the PIN could be passed programmatically to avoid a prompt to enter it.
```
    NCryptOpenKey(hProv, &hKey, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
    NCryptDeleteKey(hKey, 0);  // After this, no need to free the key handle
```

# License

MIT License