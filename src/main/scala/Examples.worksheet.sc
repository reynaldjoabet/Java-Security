import java.io.FileInputStream
import java.io.InputStream
import java.net.InetAddress
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathParameters
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXRevocationChecker
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
import java.util.Base64
import java.util.EnumSet

import scala.io.Source

import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import sun.security.x509.X509CertImpl

val trustManagerFactory =
  TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
//X509ExtendedTrustManager

TrustManagerFactory.getDefaultAlgorithm()

KeyManagerFactory.getDefaultAlgorithm()
KeyManagerFactory.getInstance("PKIX")

val keyFactory = KeyFactory.getInstance("EC")

val keyFactory2 = KeyFactory.getInstance("RSA")

val keyFactory3 = KeyFactory.getInstance("EdDSA")

val keyFactory4 = KeyFactory.getInstance("Ed25519")
val keyFactory5 = KeyFactory.getInstance("Ed448")

keyFactory.getProvider
keyFactory2.getProvider
keyFactory3.getProvider
keyFactory4.getProvider
keyFactory5.getProvider

keyFactory.getAlgorithm
keyFactory2.getAlgorithm
keyFactory3.getAlgorithm
keyFactory4.getAlgorithm
keyFactory5.getAlgorithm

CertPathBuilder.getDefaultType()
//keyFactory.generatePrivate()
var params = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType())

val cpv = CertPathValidator.getInstance("PKIX")
val rc  = cpv.getRevocationChecker().asInstanceOf[PKIXRevocationChecker]
//rc.setOptions(EnumSet.of(Option.SOFT_FAIL));
//  params.addCertPathChecker(rc);
//  val cpvr = cpv.validate(path, params);

def dnsResolver(domain: String) = InetAddress.getByName(domain).getHostAddress()

def dnsResolver3(domain: String) =
  InetAddress.getByName(domain).getCanonicalHostName()

List("google.com", "youtube.com", "localhost", "premierdev.org").map(
  dnsResolver
)
List("google.com", "youtube.com", "localhost", "premierdev.org").map(
  dnsResolver3
)

import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSessionContext
import javax.net.ServerSocketFactory

val ssf = SSLServerSocketFactory.getDefault

//val serverSocket=ssf.createServerSocket(8090)

//serverSocket

val f = new FileInputStream(
  Paths.get("src/main/resources/certifs.pem").toFile()
)

getClass().getResourceAsStream("")
import scala.jdk.CollectionConverters._

val providers = Security.getProviders()

providers.foreach(p => println(p.getName()))

providers.foreach(p => println(p.getInfo()))
providers.foreach { provider =>
  provider.getServices().asScala.foreach(ser => println(ser.getAlgorithm()))

}

// SUN
// SunRsaSign
// SunEC
// SunJSSE
// SunJCE
// SunJGSS
// SunSASL
// XMLDSig
// SunPCSC
// JdkLDAP
// JdkSASL
// SunPKCS11

// SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)
// Sun RSA signature provider
// Sun Elliptic Curve provider
// Sun JSSE provider(PKCS12, SunX509/PKIX key/trust factories, SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)
// SunJCE Provider (implements RSA, DES, Triple DES, AES, Blowfish, ARCFOUR, RC2, PBE, Diffie-Hellman, HMAC, ChaCha20)
// Sun (Kerberos v5, SPNEGO)
// Sun SASL provider(implements client mechanisms for: DIGEST-MD5, EXTERNAL, PLAIN, CRAM-MD5, NTLM; server mechanisms for: DIGEST-MD5, CRAM-MD5, NTLM)
// XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)
// Sun PC/SC provider
// JdkLDAP Provider (implements LDAP CertStore)
// JDK SASL provider(implements client and server mechanisms for GSSAPI)
// Apple Provider
// Unconfigured and unusable PKCS11 provider

Security.getProvider("SUN").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunRsaSign").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunEC").getServices().asScala.foreach(s => println(s.getAlgorithm()))

// SUN
// SunRsaSign
// SunEC
// SunJSSE
// SunJCE
// SunJGSS
// SunSASL
// XMLDSig
// SunPCSC
// JdkLDAP
// JdkSASL
// SunPKCS11

Security.getProvider("SunJSSE").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunJCE").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunJGSS").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunSASL").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("XMLDSig").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunPCSC").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("JdkLDAP").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("JdkSASL").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("SunPKCS11").getServices().asScala.foreach(s => println(s.getAlgorithm()))

Security.getProvider("Apple").getServices().asScala.foreach(s => println(s.getAlgorithm()))

def getKeyFromPassword(password: String, algorithm: String) = {
  val random = new SecureRandom()
  val salt   = Array[Byte](16)
  random.nextBytes(salt)
  val g       = scala.util.Random.alphanumeric.take(4096).map(_.toByte).toArray
  val factory = SecretKeyFactory.getInstance(algorithm)
  val spec =
    new PBEKeySpec(password.toCharArray(), g, 65536, 512); // 310,000 recommended for PBKDF2
  val originalKey =
    new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES")
  originalKey
}

val encoder = Base64.getEncoder()

encoder.encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA512").getEncoded) //).length()

encoder
  .encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA224").getEncoded())
  .length()

encoder
  .encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA512").getEncoded())
  .length()

encoder.encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA512").getEncoded())
encoder.encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA512").getEncoded())
encoder
  .encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA384").getEncoded())
  .length()

encoder.encodeToString(getKeyFromPassword("hellopassword", "PBKDF2WithHmacSHA512").getEncoded())
// PBEWithHmacSHA512
// PBEWithHmacSHA512AndAES_128
// PBEWithHmacSHA512AndAES_256
encoder
  .encodeToString(getKeyFromPassword("hellopassword", "PBEWithHmacSHA512AndAES_256").getEncoded())

import java.security.cert.CertStore
import java.security.interfaces
import java.security.spec

import javax.crypto.spec.DHGenParameterSpec
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPrivateKeySpec
import javax.crypto.spec.DHPublicKeySpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.SecretKeySpec

val pbeSpec: PBEParameterSpec = new PBEParameterSpec(Array.emptyByteArray, 65536)

//A Java keystore stores private key entries, certificates with public keys, or just secret keys that we may use for various cryptographic purposes.
KeyStore.getDefaultType()

KeyManagerFactory.getDefaultAlgorithm()

SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites()

SSLContext.getDefault().getProvider().getInfo()
SSLContext.getInstance("TLS").getProvider.getName
SSLContext.getInstance("DTLS")
//SSLContext.getInstance("TLS").createSSLEngine().beginHandshake
SSLContext.getInstance("DTLSv1.0")
SSLContext.getInstance("DTLSv1.2")
SSLContext.getInstance("TLSv1.2")
SSLContext.getInstance("TLSv1.3")

val tls2 = SSLContext.getInstance("TLSv1.2")

tls2.init(Array.empty[KeyManager], Array.empty[TrustManager], new SecureRandom())

tls2.getDefaultSSLParameters().getCipherSuites()
tls2.getDefaultSSLParameters().getCipherSuites().length
tls2.getDefaultSSLParameters().getProtocols()

tls2.createSSLEngine()

tls2.getSupportedSSLParameters().getApplicationProtocols()
SSLContext.getInstance("TLSv1.3").getClientSessionContext().getSessionTimeout()

val tls3 = SSLContext.getInstance("TLSv1.3")

tls3.init(Array.empty[KeyManager], Array.empty[TrustManager], new SecureRandom())

tls3.getDefaultSSLParameters().getCipherSuites()
tls3.getDefaultSSLParameters().getCipherSuites().length
tls3.getDefaultSSLParameters().getProtocols()
SSLSocketFactory.getDefault

val suites2 = tls2.getDefaultSSLParameters().getCipherSuites()
val suites3 = tls3.getDefaultSSLParameters().getCipherSuites()

suites3.diff(suites2)

//Array("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256")

// TLS1.3 Cipher Suites
// The following are the new collections of cipher suites used in TLS v1.3:

// TLS_AES_256_GCM_SHA384 (Enabled by default)
// TLS_CHACHA20_POLY1305_SHA256 (Enabled by default)
// TLS_AES_128_GCM_SHA256 (Enabled by default)
// TLS_AES_128_CCM_8_SHA256
// TLS_AES_128_CCM_SHA256

//The last two collections need to be explicitly added if required

val passwordProtection = new KeyStore.PasswordProtection(
  "password".toCharArray(),
  "PBEWithHmacSHA512AndAES_128",
  new PBEParameterSpec("salt".toArray.map(_.toByte), 100_000)
)

import javax.smartcardio._
import sun.security.ec
import sun.security.pkcs.PKCS7
import sun.security.pkcs.PKCS8Key
import sun.security.pkcs10.PKCS10
import sun.security.pkcs11.wrapper.PKCS11
import sun.security.pkcs11.P11TlsKeyMaterialGenerator
import sun.security.pkcs11.P11TlsMasterSecretGenerator
import sun.security.pkcs11.P11Util.getMagnitude
import sun.security.pkcs11.Secmod.TrustType
import sun.security.pkcs11.SunPKCS11
import sun.security.pkcs12.PKCS12KeyStore
import sun.security.provider
import sun.security.rsa.RSAKeyFactory
import sun.security.rsa.RSAKeyPairGenerator
import sun.security.rsa.RSAPrivateCrtKeyImpl
import sun.security.rsa.RSAPrivateKeyImpl
import sun.security.rsa.RSAPublicKeyImpl
import sun.security.rsa.RSAUtil
import sun.security.rsa.SunRsaSign
import sun.security.smartcardio.SunPCSC.Factory
import sun.security.ssl
import sun.security.ssl.RSASignature
import sun.security.ssl.SSLContextImpl
import sun.security.ssl.SSLServerSocketFactoryImpl
import sun.security.ssl.SSLSocketFactoryImpl
import sun.security.ssl.SSLSocketImpl
import sun.security.ssl.SunJSSE
import sun.security.timestamp
import sun.security.tools
import sun.security.util.AnchorCertificates
import sun.security.util.CurveDB
import sun.security.util.DerEncoder
import sun.security.util.ECUtil
import sun.security.util.GCMParameters
import sun.security.util.HexDumpEncoder
import sun.security.util.KeyStoreDelegator
import sun.security.util.KeyUtil
import sun.security.util.MessageDigestSpi2
import sun.security.util.Pem.decode
import sun.security.util.UntrustedCertificates
import sun.security.validator
import sun.security.x509

val certFactory = CertificateFactory.getInstance("X.509")
//val p=certFactory.generateCertPath(new FileInputStream("src/main/resources/certifs.pem"))

//p.getCertificates()
