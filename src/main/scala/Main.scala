import java.security.Certificate
import java.security.cert.X509Certificate
import javax.security.cert.Certificate
import javax.security.cert.X509Certificate
import java.security.cert.CertStore
import java.security.KeyStore
import java.security.spec.X509EncodedKeySpec
import java.security.Security.getProviders
import java.security.Provider
import java.security
import scala.jdk.CollectionConverters._

import sun.security.x509.CertificateX509Key
import sun.security.ec.SunEC
import sun.security.util
import sun.security.tools.keytool.CertAndKeyGen

import sun.security.ssl.SunJSSE
import sun.security.rsa.SunRsaSign

import sun.security.pkcs12.PKCS12KeyStore
import sun.security.provider.JavaKeyStore
import sun.security.pkcs12.PKCS12KeyStore
import sun.security.provider.Sun
import security.PublicKey
import apple.security.AppleProvider
import javax.crypto.SecretKeyFactory
import jdk.security.jarsigner

object Main extends App {
  println("Hello, World!")
  // KeyStore

// HmacSHA512
// HmacSHA3-384
// HmacSHA3-224
// AES
// HmacSHA384
// HmacSHA3-512
// PBEWithMD5AndDES
// HmacSHA384
// HmacSHA512/256
// HmacSHA3-224
// AES/GCM/NoPadding
// HmacSHA512/224
// HmacSHA3-256
// PBEWithSHA1AndRC2_128
// HmacSHA512/224
// HmacSHA512
// AES_192/ECB/NoPadding
// RC2
// AES_128/KW/NoPadding
// PBEWithSHA1AndRC2_40
// HmacSHA512/256
// PBEWithMD5AndDES
// PBEWithSHA1AndRC4_128
// DESede
// PBEWithSHA1AndDESede
// PBEWithSHA1AndRC4_40
// PBEWithSHA1AndRC2_128
// DiffieHellman
// PBEWithSHA1AndRC4_128
// DESedeWrap
// AES_256/KW/NoPadding
// AES/KW/NoPadding
// HmacSHA256
// PBEWithSHA1AndDESede
// PBEWithSHA1AndRC4_40
// AES_192/KWP/NoPadding
// PBEWithSHA1AndRC4_40
// PBEWithSHA1AndDESede
// PBEWithHmacSHA224AndAES_128
// PBEWithSHA1AndRC4_128
// PBEWithSHA1AndRC2_40
// HmacPBESHA512/224
// PBEWithMD5AndTripleDES
// PBEWithSHA1AndRC2_128
// ChaCha20-Poly1305
// AES
// PBEWithSHA1AndRC2_40
// HmacSHA3-512
// DiffieHellman
// HmacSHA3-256
// HmacSHA3-384
// AES_192/OFB/NoPadding
// AES_192/CFB/NoPadding
// AES_192/KW/NoPadding
// SunTlsPrf
// AES_192/GCM/NoPadding
// SslMacMD5
// HmacSHA224
// PBEWithMD5AndDES
// PBKDF2WithHmacSHA1
// AES_192/CBC/NoPadding
// PBEWithHmacSHA512
// AES_128/KW/PKCS5Padding
// DESede
// SunTlsKeyMaterial
// AES_256/KW/PKCS5Padding
// OAEP
// AES_128/ECB/NoPadding
// SunTlsMasterSecret
// AES_256/ECB/NoPadding
// ChaCha20-Poly1305
// PBEWithHmacSHA224AndAES_128
// DiffieHellman
// PBKDF2WithHmacSHA384
// AES/KW/PKCS5Padding
// ARCFOUR
// DESede
// ARCFOUR
// AES_256/GCM/NoPadding
// HmacPBESHA512/256
// SunTls12Prf
// Blowfish
// PBEWithHmacSHA256
// PBEWithHmacSHA224AndAES_128
// HmacPBESHA384
// PBEWithHmacSHA1AndAES_256
// PBKDF2WithHmacSHA256
// RC2
// PBEWithHmacSHA384AndAES_256
// RSA
// HmacPBESHA256
// HmacSHA256
// AES_128/CFB/NoPadding
// PBES2
// HmacSHA1
// AES
// AES_128/KWP/NoPadding
// DiffieHellman
// AES_128/OFB/NoPadding
// AES_256/KWP/NoPadding
// ChaCha20
// PBEWithHmacSHA224AndAES_256
// HmacSHA224
// PBEWithMD5AndTripleDES
// DES
// SslMacSHA1
// PBEWithHmacSHA384
// PBEWithHmacSHA224AndAES_256
// DES
// AES_256/CBC/NoPadding
// PBEWithHmacSHA384AndAES_128
// HmacSHA1
// PBKDF2WithHmacSHA224
// PBEWithHmacSHA256AndAES_256
// HmacPBESHA224
// PBEWithHmacSHA512AndAES_256
// HmacMD5
// HmacMD5
// DESede
// PBEWithHmacSHA512AndAES_128
// PBEWithHmacSHA256AndAES_128
// AES/KWP/NoPadding
// PBEWithHmacSHA512AndAES_128
// AES_192/KW/PKCS5Padding
// PBEWithHmacSHA512AndAES_256
// HmacPBESHA1
// SunTlsRsaPremasterSecret
// AES_256/CFB/NoPadding
// PBEWithHmacSHA256AndAES_128
// PBEWithHmacSHA512AndAES_128
// PBEWithHmacSHA1AndAES_128
// Blowfish
// PBEWithHmacSHA224
// PBEWithHmacSHA256AndAES_256
// DiffieHellman
// PBEWithHmacSHA1
// PBEWithHmacSHA512AndAES_256
// PBEWithHmacSHA384AndAES_256
// PBEWithHmacSHA1AndAES_128
// DES
// AES_128/CBC/NoPadding
// PBEWithHmacSHA224AndAES_256
// AES_256/OFB/NoPadding
// PBEWithHmacSHA384AndAES_128
// DES
// PBEWithHmacSHA1AndAES_128
// PBEWithHmacSHA1AndAES_256
// PBEWithHmacSHA384AndAES_256
// AES_128/GCM/NoPadding
// PBEWithHmacSHA1AndAES_256
// PBEWithHmacSHA256AndAES_256
// RC2
// JCEKS
// PBEWithHmacSHA384AndAES_128
// Blowfish
// GCM
// PBKDF2WithHmacSHA512
// ChaCha20
// PBEWithHmacSHA256AndAES_128
// HmacPBESHA512
// PBEWithMD5AndTripleDES

  // password-based encryption(PBE)

//PBEWithHmacSHA256
// PBEWithHmacSHA256AndAES_128
//PBEWithHmacSHA256AndAES_256

//PBEWithHmacSHA224
//PBEWithHmacSHA224AndAES_128
// PBEWithHmacSHA224AndAES_256

// PBEWithHmacSHA384
//PBEWithHmacSHA384AndAES_128
//PBEWithHmacSHA384AndAES_256

//AES-128 provides encryption capabilities, while HMAC-SHA512 provides key derivation and integrity verification. This combination offers both encryption and integrity protection for the data being encrypted.
//hmacSHA(Hash-based Message Authentication Code with Secure Hash Algorithm)
// PBEWithHmacSHA512
// PBEWithHmacSHA512AndAES_128
// PBEWithHmacSHA512AndAES_256

  val skf1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")

  val skf512 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")

  val skf224 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA224")

  val skf384 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384")
//PBKDF2WithHmacSHA224
///PBKDF2WithHmacSHA512
// PBKDF2WithHmacSHA384

//PBKDF2 is a Password-Based Key Derivation Function in which a key is generated from the Password. The generated key can be used as an encryption key or as a hash value that needs to be stored in the database.
}
