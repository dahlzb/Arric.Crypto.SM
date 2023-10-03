# Arric.Crypto.SM

国密加密算法，支持 SM2、SM3、SM4

### SM2

#### 生成密钥
``` C# 
var sm2 = new SM2.SM2Crypto();
var generateKeyHex = sm2.GenerateSecretKeyPair(true);
var generateKeyBase64 = sm2.GenerateSecretKeyPair(false);
```

#### 加密
``` C# 
var encHex = sm2.EncryptToHex(Plaintext, PublicKeyHex, true);
var encBase64 = sm2.EncryptToBase64(Plaintext, PublicKeyHex, true);
```

#### 解密
``` C# 
var decHex = sm2.DecryptFormHex(encHex, PrivateKeyHex, true);
var decBase64 = sm2.DecryptFormBase64(encBase64, PrivateKeyHex, true);
```

### SM3

``` C#
var sm3 = new SM3.SM3Crypto();
var encryptHex = sm3.EncryptToHex(Plaintext);
var encryptBase64= sm3.EncryptToBase64(Plaintext);
```


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


