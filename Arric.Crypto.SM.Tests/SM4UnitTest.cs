using Arric.Crypto.SM.SM4;
using System;
using System.Text;

namespace DahlZb.Tools.Common.Security.UnitTest
{
    [TestClass]
    public class SM4UnitTest
    {
        private readonly string Plaintext = "Hello,World! 【你好，世界！】 {1234}";
        private readonly string SecretKey = "85E9166652184B0A";
        private readonly string IV = "198C60C9876E44D6";
        private readonly string SecretKeyHex = "38354539313636363532313834423041";
        private readonly string IVHex = "31393843363043393837364534344436";

        [TestMethod("SM4 ECB 加密 UTF8")]
        public void EncryptECBUtf8()
        {
            var sm4Crypto = new Sm4Crypto();

            var ecbBase64 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKey);
            var ecbHex = sm4Crypto.EncryptECBToHex(Plaintext, SecretKey);
            Assert.AreEqual("zFuKV51HMMWmTowFdSVzspomBDQ4SNrdrpF1vRrQboit6pW3kbqP8JahmaqQqZD8", ecbBase64);
            Assert.AreEqual("cc5b8a579d4730c5a64e8c05752573b29a2604343848daddae9175bd1ad06e88adea95b791ba8ff096a199aa90a990fc", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.EncryptECBToHex(Plaintext, SecretKeyHex, isHexSecretKey: true);
            Assert.AreEqual("zFuKV51HMMWmTowFdSVzspomBDQ4SNrdrpF1vRrQboit6pW3kbqP8JahmaqQqZD8", ecbBase642);
            Assert.AreEqual("cc5b8a579d4730c5a64e8c05752573b29a2604343848daddae9175bd1ad06e88adea95b791ba8ff096a199aa90a990fc", ecbHex2);
        }

        [TestMethod("SM4 ECB 加密 Ascii")]
        public void EncryptECBAscii()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.ASCII;

            var ecbBase64 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKey);
            var ecbHex = sm4Crypto.EncryptECBToHex(Plaintext, SecretKey);
            Assert.AreEqual("KcsMlP7Ytg6hGS9ufPImpRlTpeHSmj81wrruRxTTGo0=", ecbBase64);
            Assert.AreEqual("29cb0c94fed8b60ea1192f6e7cf226a51953a5e1d29a3f35c2baee4714d31a8d", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.EncryptECBToHex(Plaintext, SecretKeyHex, isHexSecretKey: true);
            Assert.AreEqual("KcsMlP7Ytg6hGS9ufPImpRlTpeHSmj81wrruRxTTGo0=", ecbBase642);
            Assert.AreEqual("29cb0c94fed8b60ea1192f6e7cf226a51953a5e1d29a3f35c2baee4714d31a8d", ecbHex2);
        }

        [TestMethod("SM4 ECB 加密 Unicode")]
        public void EncryptECBUnicode()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.Unicode;

            var ecbBase64 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKey);
            var ecbHex = sm4Crypto.EncryptECBToHex(Plaintext, SecretKey);
            Assert.AreEqual("zzKNA+m54FtTl3TFHxHENa7/0Uel0CyqbT1+IZwRGCuK9K8NrGrDXFl8sBdXUpxopFVfAUO6KqZEoaz5CAWkEQ==", ecbBase64);
            Assert.AreEqual("cf328d03e9b9e05b539774c51f11c435aeffd147a5d02caa6d3d7e219c11182b8af4af0dac6ac35c597cb01757529c68a4555f0143ba2aa644a1acf90805a411", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptECBToBase64(Plaintext, SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.EncryptECBToHex(Plaintext, SecretKeyHex, isHexSecretKey: true);
            Assert.AreEqual("ISZpMS1vyRLpZHXKcbyOcm6si7++VfSduwedG2xHs/8L91YZmzXYq55rttIcLjVo0CzSBLiqf02lcxxUzAXbLw==", ecbBase642);
            Assert.AreEqual("212669312d6fc912e96475ca71bc8e726eac8bbfbe55f49dbb079d1b6c47b3ff0bf756199b35d8ab9e6bb6d21c2e3568d02cd204b8aa7f4da5731c54cc05db2f", ecbHex2);
        }

        [TestMethod("SM4 ECB 解密 UTF8")]
        public void DecryptECBUtf8()
        {
            var sm4Crypto = new Sm4Crypto();

            var ecbBase64 = sm4Crypto.DecryptECBFormBase64("zFuKV51HMMWmTowFdSVzspomBDQ4SNrdrpF1vRrQboit6pW3kbqP8JahmaqQqZD8", SecretKey);
            var ecbHex = sm4Crypto.DecryptECBFormHex("cc5b8a579d4730c5a64e8c05752573b29a2604343848daddae9175bd1ad06e88adea95b791ba8ff096a199aa90a990fc", SecretKey);
            Assert.AreEqual(Plaintext, ecbBase64);
            Assert.AreEqual(Plaintext, ecbHex);

            var ecbBase642 = sm4Crypto.DecryptECBFormBase64("zFuKV51HMMWmTowFdSVzspomBDQ4SNrdrpF1vRrQboit6pW3kbqP8JahmaqQqZD8", SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.DecryptECBFormHex("cc5b8a579d4730c5a64e8c05752573b29a2604343848daddae9175bd1ad06e88adea95b791ba8ff096a199aa90a990fc", SecretKeyHex, true);
            Assert.AreEqual(Plaintext, ecbBase642);
            Assert.AreEqual(Plaintext, ecbHex2);
        }

        [TestMethod("SM4 ECB 解密 Ascii")]
        public void DecryptECBAscii()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.ASCII;

            var ecbBase64 = sm4Crypto.DecryptECBFormBase64("KcsMlP7Ytg6hGS9ufPImpRlTpeHSmj81wrruRxTTGo0=", SecretKey);
            var ecbHex = sm4Crypto.DecryptECBFormHex("29cb0c94fed8b60ea1192f6e7cf226a51953a5e1d29a3f35c2baee4714d31a8d", SecretKey);
            Assert.AreEqual("Hello,World! ???????? {1234}", ecbBase64);
            Assert.AreEqual("Hello,World! ???????? {1234}", ecbHex);

            var ecbBase642 = sm4Crypto.DecryptECBFormBase64("KcsMlP7Ytg6hGS9ufPImpRlTpeHSmj81wrruRxTTGo0=", SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.DecryptECBFormHex("29cb0c94fed8b60ea1192f6e7cf226a51953a5e1d29a3f35c2baee4714d31a8d", SecretKeyHex, true);
            Assert.AreEqual("Hello,World! ???????? {1234}", ecbBase642);
            Assert.AreEqual("Hello,World! ???????? {1234}", ecbHex2);
        }

        [TestMethod("SM4 ECB 解密 Unicode")]
        public void DecryptECBUnicode()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.Unicode;

            var ecbBase64 = sm4Crypto.DecryptECBFormBase64("zzKNA+m54FtTl3TFHxHENa7/0Uel0CyqbT1+IZwRGCuK9K8NrGrDXFl8sBdXUpxopFVfAUO6KqZEoaz5CAWkEQ==", SecretKey);
            var ecbHex = sm4Crypto.DecryptECBFormHex("cf328d03e9b9e05b539774c51f11c435aeffd147a5d02caa6d3d7e219c11182b8af4af0dac6ac35c597cb01757529c68a4555f0143ba2aa644a1acf90805a411", SecretKey);
            Assert.AreEqual(Plaintext, ecbBase64);
            Assert.AreEqual(Plaintext, ecbHex);

            var ecbBase642 = sm4Crypto.DecryptECBFormBase64("ISZpMS1vyRLpZHXKcbyOcm6si7++VfSduwedG2xHs/8L91YZmzXYq55rttIcLjVo0CzSBLiqf02lcxxUzAXbLw==", SecretKeyHex, true);
            var ecbHex2 = sm4Crypto.DecryptECBFormHex("212669312d6fc912e96475ca71bc8e726eac8bbfbe55f49dbb079d1b6c47b3ff0bf756199b35d8ab9e6bb6d21c2e3568d02cd204b8aa7f4da5731c54cc05db2f", SecretKeyHex, true);
            Assert.AreEqual(Plaintext, ecbBase642);
            Assert.AreEqual(Plaintext, ecbHex2);
        }

        [TestMethod("SM4 CBC 加密 UTF8")]
        public void EncryptCBCUtf8()
        {
            var sm4Crypto = new Sm4Crypto();
            var ecbBase64 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IV);
            var ecbHex = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IV);
            Assert.AreEqual("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", ecbBase64);
            Assert.AreEqual("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IV, true, false);
            var ecbHex2 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IV, isHexSecretKey: true, false);
            Assert.AreEqual("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", ecbBase642);
            Assert.AreEqual("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", ecbHex2);

            var ecbBase643 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IVHex, false, true);
            Assert.AreEqual("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", ecbBase643);
            Assert.AreEqual("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", ecbHex3);

            var ecbBase644 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            var ecbHex4 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            Assert.AreEqual("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", ecbBase644);
            Assert.AreEqual("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", ecbHex4);
        }

        [TestMethod("SM4 CBC 加密 Ascii")]
        public void EncryptCBCAscii()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.ASCII;
            var ecbBase64 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IV);
            var ecbHex = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IV);
            Assert.AreEqual("LMoLgxbBPw/eMZT1/HCn95ylfFMvkGUL7BnBsKjBviA=", ecbBase64);
            Assert.AreEqual("2cca0b8316c13f0fde3194f5fc70a7f79ca57c532f90650bec19c1b0a8c1be20", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IV, true, false);
            var ecbHex2 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IV, isHexSecretKey: true, false);
            Assert.AreEqual("LMoLgxbBPw/eMZT1/HCn95ylfFMvkGUL7BnBsKjBviA=", ecbBase642);
            Assert.AreEqual("2cca0b8316c13f0fde3194f5fc70a7f79ca57c532f90650bec19c1b0a8c1be20", ecbHex2);

            var ecbBase643 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IVHex, false, true);
            Assert.AreEqual("LMoLgxbBPw/eMZT1/HCn95ylfFMvkGUL7BnBsKjBviA=", ecbBase643);
            Assert.AreEqual("2cca0b8316c13f0fde3194f5fc70a7f79ca57c532f90650bec19c1b0a8c1be20", ecbHex3);

            var ecbBase644 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            var ecbHex4 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            Assert.AreEqual("LMoLgxbBPw/eMZT1/HCn95ylfFMvkGUL7BnBsKjBviA=", ecbBase644);
            Assert.AreEqual("2cca0b8316c13f0fde3194f5fc70a7f79ca57c532f90650bec19c1b0a8c1be20", ecbHex4);
        }

        [TestMethod("SM4 CBC 加密 Unicode")]
        public void EncryptCBCUnicode()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.Unicode;
            var ecbBase64 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IV);
            var ecbHex = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IV);
            Assert.AreEqual("p0LiPuRZsje1faOPnmWxXB6VpyyVfaGzwixDb5CvV5s/VXLWBgvWZGnk21O9FJrHQNb9elSg66xbZlSgtNgqZQ==", ecbBase64);
            Assert.AreEqual("a742e23ee459b237b57da38f9e65b15c1e95a72c957da1b3c22c436f90af579b3f5572d6060bd66469e4db53bd149ac740d6fd7a54a0ebac5b6654a0b4d82a65", ecbHex);

            var ecbBase642 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IV, true, false);
            var ecbHex2 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IV, isHexSecretKey: true, false);
            Assert.AreEqual("JODef4Pb/rpB8jfJ8fodbnHKlOBLShRqycuwZ6f2QvPCID1ElS61WQ8lwmo6amS6XGjg8YkcPNENzk00EaZQtw==", ecbBase642);
            Assert.AreEqual("24e0de7f83dbfeba41f237c9f1fa1d6e71ca94e04b4a146ac9cbb067a7f642f3c2203d44952eb5590f25c26a3a6a64ba5c68e0f1891c3cd10dce4d3411a650b7", ecbHex2);

            var ecbBase643 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKey, IVHex, false, true);
            Assert.AreEqual("mex+2F4pU5v8gw8aekagBEPF0J4K6nQAR0pGI/8OxP5QT0F7FZI1RmmcSki8q7jjiMBlpRjOuqzyz6nioe8HQw==", ecbBase643);
            Assert.AreEqual("99ec7ed85e29539bfc830f1a7a46a00443c5d09e0aea7400474a4623ff0ec4fe504f417b15923546699c4a48bcabb8e388c065a518cebaacf2cfa9e2a1ef0743", ecbHex3);

            var ecbBase644 = sm4Crypto.EncryptCBCToBase64(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            var ecbHex4 = sm4Crypto.EncryptCBCToHex(Plaintext, SecretKeyHex, IVHex, true, isHexIv: true);
            Assert.AreEqual("dPGSAnRpcxSmV50fRMF6FzksjFC/IPUhJz6MFsLLHMLLy1BLbgfchy5a6Vf6lcc8et3BeNx9JiBVxrUSZ4SVDQ==", ecbBase644);
            Assert.AreEqual("74f1920274697314a6579d1f44c17a17392c8c50bf20f521273e8c16c2cb1cc2cbcb504b6e07dc872e5ae957fa95c73c7addc178dc7d262055c6b5126784950d", ecbHex4);
        }

        [TestMethod("SM4 CBC 解密 UTF8")]
        public void DecryptCBCUtf8()
        {
            var sm4Crypto = new Sm4Crypto();
            var ecbBase64 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKey, IV);
            var ecbHex = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKey, IV);
            Assert.AreEqual(Plaintext, ecbBase64);
            Assert.AreEqual(Plaintext, ecbHex);

            var ecbBase642 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKeyHex, IV, true);
            var ecbHex2 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKeyHex, IV, true);
            Assert.AreEqual(Plaintext, ecbBase642);
            Assert.AreEqual(Plaintext, ecbHex2);

            var ecbBase643 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKey, IVHex, false, true);
            Assert.AreEqual(Plaintext, ecbBase643);
            Assert.AreEqual(Plaintext, ecbHex3);

            var ecbBase644 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKeyHex, IVHex, true, true);
            var ecbHex4 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKeyHex, IVHex, true, true);
            Assert.AreEqual(Plaintext, ecbBase644);
            Assert.AreEqual(Plaintext, ecbHex4);
        }

        [TestMethod("SM4 CBC 解密 Ascii")]
        public void DecryptCBCAscii()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.ASCII;
            var ecbBase64 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKey, IV);
            var ecbHex = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKey, IV);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbBase64);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbHex);

            var ecbBase642 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKeyHex, IV, true);
            var ecbHex2 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKeyHex, IV, true);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbBase642);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbHex2);

            var ecbBase643 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKey, IVHex, false, true);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbBase643);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbHex3);

            var ecbBase644 = sm4Crypto.DecryptCBCFormBase64("l4UGPBnKXN8INky7SsEqYP9s6iPZZKt5wQDLY+EtQgAp15xZ7FA66hdATNRHiT6D", SecretKeyHex, IVHex, true, true);
            var ecbHex4 = sm4Crypto.DecryptCBCFormHex("9785063c19ca5cdf08364cbb4ac12a60ff6cea23d964ab79c100cb63e12d420029d79c59ec503aea17404cd447893e83", SecretKeyHex, IVHex, true, true);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbBase644);
            Assert.AreEqual("Hello,World! ???????????????????????? {1234}", ecbHex4);
        }

        [TestMethod("SM4 CBC 解密 Unicode")]
        public void DecryptCBCUnicode()
        {
            var sm4Crypto = new Sm4Crypto();
            sm4Crypto.Encoding = Encoding.Unicode;
            var ecbBase64 = sm4Crypto.DecryptCBCFormBase64("p0LiPuRZsje1faOPnmWxXB6VpyyVfaGzwixDb5CvV5s/VXLWBgvWZGnk21O9FJrHQNb9elSg66xbZlSgtNgqZQ==", SecretKey, IV);
            var ecbHex = sm4Crypto.DecryptCBCFormHex("a742e23ee459b237b57da38f9e65b15c1e95a72c957da1b3c22c436f90af579b3f5572d6060bd66469e4db53bd149ac740d6fd7a54a0ebac5b6654a0b4d82a65", SecretKey, IV);
            Assert.AreEqual(Plaintext, ecbBase64);
            Assert.AreEqual(Plaintext, ecbHex);

            var ecbBase642 = sm4Crypto.DecryptCBCFormBase64("JODef4Pb/rpB8jfJ8fodbnHKlOBLShRqycuwZ6f2QvPCID1ElS61WQ8lwmo6amS6XGjg8YkcPNENzk00EaZQtw==", SecretKeyHex, IV, true);
            var ecbHex2 = sm4Crypto.DecryptCBCFormHex("24e0de7f83dbfeba41f237c9f1fa1d6e71ca94e04b4a146ac9cbb067a7f642f3c2203d44952eb5590f25c26a3a6a64ba5c68e0f1891c3cd10dce4d3411a650b7", SecretKeyHex, IV, true);
            Assert.AreEqual(Plaintext, ecbBase642);
            Assert.AreEqual(Plaintext, ecbHex2);

            var ecbBase643 = sm4Crypto.DecryptCBCFormBase64("mex+2F4pU5v8gw8aekagBEPF0J4K6nQAR0pGI/8OxP5QT0F7FZI1RmmcSki8q7jjiMBlpRjOuqzyz6nioe8HQw==", SecretKey, IVHex, false, true);
            var ecbHex3 = sm4Crypto.DecryptCBCFormHex("99ec7ed85e29539bfc830f1a7a46a00443c5d09e0aea7400474a4623ff0ec4fe504f417b15923546699c4a48bcabb8e388c065a518cebaacf2cfa9e2a1ef0743", SecretKey, IVHex, false, true);
            Assert.AreEqual(Plaintext, ecbBase643);
            Assert.AreEqual(Plaintext, ecbHex3);

            var ecbBase644 = sm4Crypto.DecryptCBCFormBase64("dPGSAnRpcxSmV50fRMF6FzksjFC/IPUhJz6MFsLLHMLLy1BLbgfchy5a6Vf6lcc8et3BeNx9JiBVxrUSZ4SVDQ==", SecretKeyHex, IVHex, true, true);
            var ecbHex4 = sm4Crypto.DecryptCBCFormHex("74f1920274697314a6579d1f44c17a17392c8c50bf20f521273e8c16c2cb1cc2cbcb504b6e07dc872e5ae957fa95c73c7addc178dc7d262055c6b5126784950d", SecretKeyHex, IVHex, true, true);
            Assert.AreEqual(Plaintext, ecbBase644);
            Assert.AreEqual(Plaintext, ecbHex4);
        }
    }
}
