using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arric.Crypto.SM.Tests
{
    [TestClass]
    public class SM3UnitTest
    {
        private readonly string Plaintext = "Hello,World! 【你好，世界！】 {1234}";

        [TestMethod("SM3 加密 UTF8")]
        public void EncryptUtf8()
        {
            var sm3 = new SM3.SM3Crypto();
            var encryptHex = sm3.EncryptToHex(Plaintext);
            var encryptBase64= sm3.EncryptToBase64(Plaintext);
            Assert.AreEqual("bf20b5edd9bae9435968792b26ee723efbc894f55600d34dc0f49396ced9763f", encryptHex);
            Assert.AreEqual("vyC17dm66UNZaHkrJu5yPvvIlPVWANNNwPSTls7Zdj8=", encryptBase64);
        }
    }
}
