# Cards

Some information of the cards are not listed by venders, but all of those cards are of **JavaCard 3.0.5** with **ECC support**.

## TianAnXin - SCP03 Card

https://item.taobao.com/item.htm?id=797321051069

### Known information

- NXP SmartMX3 chip
- GP2.3
- SCP03
- Usable memories (tested by actually allocating):
  - EEPROM: ~70K
  - RAM: ~3.8K

> This is probably a J3R180 card as I bought one with the same IC batch as the J3R180 card.

### Capabilities

```
Supports SCP03 i=00 i=10 i=20 i=60 i=70 with AES-128 AES-196 AES-256
Supported DOM privileges: SecurityDomain, DAPVerification, DelegatedManagement, CardReset, MandatedDAPVerification, TrustedPath, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration, CipheredLoadFileDataBlock
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: SHA-256
Supported Token Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Supported Receipt Generation ciphers: DES_MAC, CMAC_AES128
Supported DAP Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Version:   1 (0x01) ID:   1 (0x01) type: AES          length:  16 (AES-128)
Version:   1 (0x01) ID:   2 (0x02) type: AES          length:  16 (AES-128)
Version:   1 (0x01) ID:   3 (0x03) type: AES          length:  16 (AES-128)
```

## TianAnXin - J3R180 Card

https://item.taobao.com/item.htm?id=944020539101

### Known information

- J3R180
- GP2.3
- SCP02
- Usable memories (tested by actually allocating):
  - EEPROM: ~73K
  - RAM: ~3.8K

### Capabilities

```
Supports SCP02 i=15 i=35 i=55 i=75
Supported DOM privileges: SecurityDomain, DAPVerification, DelegatedManagement, CardReset, MandatedDAPVerification, TrustedPath, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration, CipheredLoadFileDataBlock
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: SHA-256
Supported Token Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Supported Receipt Generation ciphers: DES_MAC, CMAC_AES128
Supported DAP Verification ciphers: RSA1024_SHA1, RSAPSS_SHA256, CMAC_AES128, CMAC_AES192, CMAC_AES256, ECCP256_SHA256
Version:   1 (0x01) ID:   1 (0x01) type: DES3         length:  16
Version:   1 (0x01) ID:   2 (0x02) type: DES3         length:  16
Version:   1 (0x01) ID:   3 (0x03) type: DES3         length:  16
```
