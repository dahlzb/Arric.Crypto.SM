# Arric.Crypto.SM

国密 SM4 加密算法

### SM4

#### 加密

``` C#
var sm4Crypto = new Sm4Crypto();
var ecbBase64 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKey);
var ecbHex = sm4Crypto.EncryptECBToHex(Plaintext, SecretKey);
```

#### 解密

``` C#
var sm4Crypto = new Sm4Crypto();
var ecbBase64 = sm4Crypto.DecryptECBFormBase64(ciphertext, SecretKey);
var ecbHex = sm4Crypto.DecryptECBFormHex(ciphertext, SecretKey);
```
