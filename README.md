# Crescendo Management Tutorial

Smart Cards provide an isolated secure computing environment that is ideally suited for storing secret keys, especially those used for authentication and digital signatures. HID&reg; [Crescendo&reg; C2300](http://www.hidglobal.com/products/cards-and-credentials/crescendo/c2300) and [Crescendo&reg; Key](https://www.hidglobal.com/products/cards-and-credentials/crescendo/crescendo-key) allow companies and individuals to prevent breaches by removing the most common attack vector: passwords.

Crescendo&reg; devices support FIDO2, OATH and PIV (PKI) protocols. The sample in this repository focuses on using the PKI capabilities of the devices, but you may be interested in looking also at the [Crescendo&amp; FIDO Sample](https://glitch.com/~crescendo-webauthn)

## Crescendo Card Issuance

The Windows [Cryptogpraphic API: Next Generation](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx) provides a low level API to manage key material and certificates in smart cards.

While manually issuing a card for a user and then using that card for operations such as logging on to Windows, accessing a VPN or digitally signing an email or Office document do not require any development, there may be cases when the lifecycle of the card needs to be managed by a specialized tool that enables more granular control of the contents of each individual card. In general, to issue a card a developer would go through the following process that is illustrated in the working example in this repository.

Issuance of a Crescendo C1150 smart card makes use of the [CNG Key Storage Functions](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376208(v=vs.85).aspx)

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