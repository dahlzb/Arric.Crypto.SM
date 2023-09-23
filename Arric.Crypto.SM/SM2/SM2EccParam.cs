using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arric.Crypto.SM.SM2
{
    /// <summary>
    /// SM2椭圆曲线参数
    /// </summary>
    internal class SM2EccParam
    {
        public static SM2EccParam Instance
        {
            get
            {
                return new SM2EccParam();
            }
        }

        /// <summary>
        /// 椭圆曲线参数
        /// </summary>
        public readonly string[] EccParam = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        };

        /// <summary>
        /// 椭圆曲线参数P
        /// </summary>
        public BigInteger EccP;

        /// <summary>
        /// 椭圆曲线参数A
        /// </summary>
        public BigInteger EccA;

        /// <summary>
        /// 椭圆曲线参数B
        /// </summary>
        public BigInteger EccB;

        /// <summary>
        /// 椭圆曲线参数N
        /// </summary>
        public BigInteger EccN;

        /// <summary>
        /// 椭圆曲线参数Gx
        /// </summary>
        public BigInteger EccGx;

        /// <summary>
        /// 椭圆曲线参数Gy
        /// </summary>
        public BigInteger EccGy;

        /// <summary>
        /// 椭圆曲线
        /// </summary>
        public Org.BouncyCastle.Math.EC.ECCurve EccCurve;

        /// <summary>
        /// 椭圆曲线的点G
        /// </summary>
        public Org.BouncyCastle.Math.EC.ECPoint EccPointG;

        /// <summary>
        /// 椭圆曲线 bc规范
        /// </summary>
        public ECDomainParameters EccBcSpec;

        /// <summary>
        /// 椭圆曲线密钥对生成器
        /// </summary>
        public readonly ECKeyPairGenerator EccKeyPairGenerator;

        public SM2EccParam()
        {
            this.EccP = new BigInteger(EccParam[0], 16);
            this.EccA = new BigInteger(EccParam[1], 16);
            this.EccB = new BigInteger(EccParam[2], 16);
            this.EccN = new BigInteger(EccParam[3], 16);
            this.EccGx = new BigInteger(EccParam[4], 16);
            this.EccGy = new BigInteger(EccParam[5], 16);

            this.EccCurve = new FpCurve(EccP, EccA, EccB, EccN, BigInteger.One);
            this.EccPointG = this.EccCurve.CreatePoint(this.EccGx, this.EccGy);
            this.EccBcSpec = new ECDomainParameters(this.EccCurve, this.EccPointG, this.EccN);

            var ecKeyGenerationParam = new ECKeyGenerationParameters(EccBcSpec, new SecureRandom());

            EccKeyPairGenerator = new ECKeyPairGenerator();
            EccKeyPairGenerator.Init(ecKeyGenerationParam);
        }
    }
}
