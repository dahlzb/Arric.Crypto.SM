# Arric.Crypto.SM

���� SM4 �����㷨

### SM4

#### ����

``` C#
var sm4Crypto = new Sm4Crypto();
var ecbBase64 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKey);
var ecbHex = sm4Crypto.EncryptECBToHex(Plaintext, SecretKey);
```

#### ����

``` C#
var sm4Crypto = new Sm4Crypto();
var ecbBase64 = sm4Crypto.DecryptECBFormBase64(ciphertext, SecretKey);
var ecbHex = sm4Crypto.DecryptECBFormHex(ciphertext, SecretKey);
```
