# Crescendo C1150 Tutorial

Smart cards provide an isolated computing environment ideal for protection of highly valuable assets such as cryptographic keys. Smart cards with cryptographic capabilities like the [HID Crescendo C1150](http://www.hidglobal.com/products/cards-and-credentials/crescendo/c1150) enable system administrators and developers to greatly enhance their security posture and integrate tightly into the Windows infrastructure.

At the end of the 20th century, the value of smart cards as security devices started to become popular and two main alternatives emerged for developers to leverage their capabilities without having to deal with low level card commands and data structure. On one hand there was the [RSA Labs PKCS#11 Initiative](ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf) and on the other the different [Microft Cryptography](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380255(v=vs.85).aspx) APIs.

Those standards have helped foster adoption of smart cards, but they have aged and lessons learned have helped the emergence of new approaches that provide better abstraction enabling developers to be more productive as well as extensibility to be able to incorporate new algorithms such as Elliptic Curve Cryptography or proprietary government algoritms in countries that require them.

The [Cryptogpraphic API: Next Generation](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx) provides a modern alternative to those legacy libraries and the HID Crescendo C1150 integrates seamlessly in that ecosystem providing a cost-effective, easy to deploy high security user identity device.

## Crescendo Card Issuance

While manually issuing a card for a user and then using that card for operations such as logging on to Windows, accessing a VPN or digitally signing an email or Office document do not require any development, there may be cases when the lifecycle of the card needs to be managed by a specialized tool that enables more granular control of the contents of each individual card. In general, to issue a card a developer would go through the following process that is illustrated in the working example in this repository.

Issuance of a Crescendo C1150 smart card makes use of the [CNG Key Storage Functions](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376208(v=vs.85).aspx)

1. Connect to the smart card.
    NCryptOpenStorageProvider(&hProv, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);

2. If needed, retrieve the unique card serial number
    NCryptGetProperty(hProv, NCRYPT_SMARTCARD_GUID_PROPERTY, pbSerial, cbSerial, &cbSerial, 0);

3. Create a new persisted key, setting the desired length. It is possible to programatically pass the value of the card PIN and request the operation to be silent so no user interface is displayed. Alternatively, if the PIN is not passed Windows will display a dialog box prompting the user to enter the smart card PIN value. The default PIN of Crescendo smart cards is '00000000'.
    NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
    NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (LPBYTE)&dwKeyLen, 4, 0);
    NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (LPBYTE)szPin, 8, 0);
    NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);

4. Keys are generated and used in the trusted execution environment provided by the smart card. The public key can be exported in order to create a certificate request and submit it to a certification authoritiy. The certificate can be then added to the keypair.
    NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pbRawKey, cbRawKey, &cbRawKey, 0);
    NCryptSetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCert, cbCert, 0);

5. Keys (and their associated certificates) can also be deleted from the smart card. Again, the PIN could be passed programmatically to avoid a prompt to enter it.
    NCryptOpenKey(hProv, &hKey, L"Crescendo C1150 Key", AT_SIGNATURE, 0);
    NCryptDeleteKey(hKey, 0);  // After this, no need to free the key handle

# License

MIT License