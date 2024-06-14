import java.io.FileInputStream
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.DSAGenParameterSpec
import java.security.spec.DSAParameterSpec
import java.security.spec.DSAPrivateKeySpec
import java.security.spec.DSAPublicKeySpec
import java.security.spec.ECField
import java.security.spec.ECFieldF2m
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EdDSAParameterSpec
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.EllipticCurve
import java.security.spec.EncodedKeySpec
import java.security.spec.KeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec
import java.security.spec.RSAOtherPrimeInfo
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.security.KeyFactory
import java.security.KeyStore.TrustedCertificateEntry

import scala.jdk.CollectionConverters._

import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object CertificateChainExample extends App {
// X509TrustManager
// TrustManager
// TrustManagerFactory
// TrustedCertificateEntry

  val certFactory = CertificateFactory.getInstance("X.509")

  val certificates = certFactory
    .generateCertificates(
      new FileInputStream(Paths.get("src/main/resources/certifs.pem").toFile())
    )
    .asScala
    .map(_.asInstanceOf[X509Certificate])

  certificates.foreach { cert =>
    // println(cert)
    // println(cert.getPublicKey())
  }
  val p = certFactory.generateCertPath(new FileInputStream("../src/main/resources/certifs.pem"))
  println(p.getCertificates())

}

/**
  * \- Key Derivation: The password is processed through a key derivation function (KDF) to generate
  * a cryptographic key. The key derivation process ensures that the resulting key has sufficient
  * entropy and is suitable for encryption. \- Encryption Algorithm: The file is encrypted using a
  * symmetric encryption algorithm (such as AES, DES, or 3DES) along with the derived cryptographic
  * key. Symmetric encryption algorithms use the same key for both encryption and decryption. \-
  * Encryption Process: Each block of data in the file is processed through the encryption algorithm
  * using the cryptographic key, resulting in ciphertext. The encryption process transforms the
  * plaintext data into ciphertext, which appears random and unintelligible.
  */

//Trust stores store only trusted CA certificates

// jks  only stores private keys and certificates

//jceks stores secret keys, private keys and certificates. it also uses PBE( Password based encryption) to derive the keys

// PKCS12 PFX and P12 files. usesPBFDF2 to derive encryption key
//Encryption algorithm used are DES-3( default) and AES
