using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;

namespace RSATest
{
    public class Crypto
    {
        string pubKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgRYud8nmX0FwAlgQ37wB
kOZFn5R28qXA+3hJ3oMlvOMcbl9EqmXxUKTwdAW3rGs6FnWIKJC6eN677Mg7lZDD
jgCslqZsueE4Z+MgaJ4V70xH1XelFKGEtpFmeEJ8kN25Bh4ALIbYfzpbSxOhLfUk
jOZHO6zGweC4/esZYJ3sMk3fnCnv/V5LVf/F3mOzOKqDTJsGP8yZTgU4IG7uwVyc
XFPOW2DPKcTCV5ImXb/d/iXHJn24g0NpccKBaxxVJ/MivmmkO6vcu47l6iMohICP
sdRqpF2T7G22yfcauloK0jNpaidoAG4C9i86sZHYA6QMjtOMcTC8vJ/U5PwpRNTj
ewIDAQAB
-----END PUBLIC KEY-----";

        string privKey = @"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAgRYud8nmX0FwAlgQ37wBkOZFn5R28qXA+3hJ3oMlvOMcbl9E
qmXxUKTwdAW3rGs6FnWIKJC6eN677Mg7lZDDjgCslqZsueE4Z+MgaJ4V70xH1Xel
FKGEtpFmeEJ8kN25Bh4ALIbYfzpbSxOhLfUkjOZHO6zGweC4/esZYJ3sMk3fnCnv
/V5LVf/F3mOzOKqDTJsGP8yZTgU4IG7uwVycXFPOW2DPKcTCV5ImXb/d/iXHJn24
g0NpccKBaxxVJ/MivmmkO6vcu47l6iMohICPsdRqpF2T7G22yfcauloK0jNpaido
AG4C9i86sZHYA6QMjtOMcTC8vJ/U5PwpRNTjewIDAQABAoIBAGzmwrMKYNCxywYf
N7UYzhVpPwl+3c6daa5874zKBXdR/nVa5/n9YNURIU4wWKEcIPg7lW/rkXVRKyd6
UVI/u8q75N5/brBuQgDay0eXPpgQOXXspxc9oFHJXrJMHPy2IVb4zlrCNDk5iTVQ
TSURcBFyYFwGyfNcW5TT1yf8cvyIJTui6yKDyeFoWE9y4Q3V81xEcx3wfOwmeru1
BK29UHhW2grH+RENXFsECNFjMJ4hz+2fcRqHAGVp/L9vM5p/02cJqtW9Y+w/xUxg
C+P0yZK/JTVGbELwSkGBeN08nsKVct29KK7TSMqy3IgRnbOKJuSuVaNobNG7OcpD
Z+1oWFkCgYEAuScHCMAN09rLBnQguzIBImElaHoCLGXgCHUWaLrCSylgTJde3t6A
6ZyurSEqbgxC1sMy5kdxdMRMdIw4XpZCkOVUIsdG18H84IFUJu3AlkPWVBfsIg8j
P80GdeNufEA/vrC0JIOsTh0bC3sxmuV5jjY/kG/PGO9i5oBiLlS8R5UCgYEAsnse
LUiNXbojjpmERpVls9PQVZcjdLJO0SgP0p60lorxPH/T3ASm+kYyMVF061RReKOi
/Ia1cXlPKjvJZ3D2HIOqW8NIfoY7rv/o0+N86sb1c/O2aftr+QdSfOe/rSbZbhTk
a2UuBKnoZmjXCFnmrWm1dGpUX4wGncrkLIYSes8CgYAC6xuQRr6xDSzQEDqH2NTt
vsxBJlMscfqjB31v7ymq158d9fDX4Hf1trOGJRSvIWBYVEFUIeIm7gUqfR9SVln8
QLEfzzZNplAfFcrGxk6Xz7/sGWhubQCoO8oTR59xM+4NSmm8fZrUrF7Fwo5Ym69b
z30XALwp73QGoBVsF4fUNQKBgF5dTdUvWN7HPWl1rUQMVRtA0BOQt0RJyfY3sjXv
hxdZGrab9w2KwCXu2zbMFH8fs3uPOOs+5cu7EaoItjGkvdrRmk6t7zRGEGQ0FYuB
6VfQHZJSto1OSwX9YxV7ChKoSak0Dpjhg/UfSCptH9PghGAHVdLZLQbfZ9ghn4YS
1M5tAoGAL3IRC07t8lkWVhpgTHkyV1CEAZ3S1wrr1Oszam/Ei/4dLFJWg5NAaZD0
0ssM8pmWiF2J5GK7xjPkxCcCBLltkzmSZxrmzvIsEubZTihYQI1/XPhgCr6ce2y4
SOqIwNb47a8A6zZv+wkAu0IelrLO+g4QY1GwIy+bGG53NewGPHU=
-----END RSA PRIVATE KEY-----";


        private RsaKeyParameters publicKeyParams;
        private AsymmetricCipherKeyPair keyPair;
        private RsaPrivateCrtKeyParameters privateKeyParams;
        public Crypto()
        {
            this.publicKeyParams = ReadPublicKeyFromPem(pubKey);
            this.keyPair = ReadPrivateKeyFromPem(privKey);
            this.privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        }


        public string Encrypt(string text)
        {
            IAsymmetricBlockCipher rsaEngine = new RsaEngine();
            rsaEngine.Init(true, publicKeyParams);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(text);
            // Encrypt the plaintext
            byte[] ciphertext = rsaEngine.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);
            string encryptedText = Convert.ToBase64String(ciphertext);
            return encryptedText;
        }

        public string Decrypt(string cipher)
        {
            byte[] ciphertext = Convert.FromBase64String(cipher);
            IAsymmetricBlockCipher rsaEngine = new RsaEngine();
            rsaEngine.Init(false, privateKeyParams);

            // Decrypt the ciphertext
            byte[] decryptedBytes = rsaEngine.ProcessBlock(ciphertext, 0, ciphertext.Length);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            return decryptedText;

        }

        static RsaKeyParameters ReadPublicKeyFromPem(string publicKeyString)
        {
            using (TextReader reader = new StringReader(publicKeyString))
            {
                PemReader pemReader = new PemReader(reader);
                object obj = pemReader.ReadObject();
                if (obj is RsaKeyParameters)
                {
                    return (RsaKeyParameters)obj;
                }
                throw new InvalidOperationException("Invalid public key format");
            }
        }

        static AsymmetricCipherKeyPair ReadPrivateKeyFromPem(string privateKeyString)
        {
            using (TextReader reader = new StringReader(privateKeyString))
            {
                PemReader pemReader = new PemReader(reader);
                object obj = pemReader.ReadObject();
                if (obj is AsymmetricCipherKeyPair)
                {
                    return (AsymmetricCipherKeyPair)obj;
                }
                throw new InvalidOperationException("Invalid private key format");
            }

        }
    }
 }
