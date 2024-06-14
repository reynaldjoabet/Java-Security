import java.io.FileInputStream
import java.io.File
import java.security.KeyStore
import scala.jdk.CollectionConverters._
import apple.security.AppleProvider
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator
import java.security.interfaces.RSAPublicKey

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.DSAKeyPairGenerator

import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAMultiPrimePrivateCrtKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.XECKey
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.interfaces.ECPublicKey

object Example extends App {

  val relativeCacertsPath =
    "/lib/security/cacerts".replace("/", File.separator);
  val filename            = System.getProperty("java.home") + relativeCacertsPath;
  val is                  = new FileInputStream(filename)

  val keystore = KeyStore.getInstance(KeyStore.getDefaultType());
  val password = "changeit"
  keystore.load(is, password.toCharArray())

  println(keystore.aliases().asScala.length)

  // keystore.aliases().asScala.foreach(println)

  // keystore.aliases().asScala.map(keystore.getCertificate)
  // .foreach(println)

  // keystore
  //   .aliases()
  //   .asScala
  //   .map(keystore.getCertificateChain)
  //   .foreach(println)

  // keystore.aliases().asScala.filter(_.contains("gts"))
  // .foreach(println)

  // keystore.aliases().asScala.map(keystore.isKeyEntry)
  //  .foreach(println)

  //  keystore.aliases().asScala.map(keystore.isCertificateEntry)
  //    .foreach(println)

  // keystore
  //   .getCertificateChain(
  //     "c_us [jdk]"
  //   )
  //   .foreach(println)

  val iss = new FileInputStream("./rootca.jks")

  val keystores = KeyStore.getInstance(KeyStore.getDefaultType());

  keystores.load(iss, password.toCharArray())

  keystores.aliases().asScala.foreach(println)

  keystores
    .aliases()
    .asScala
    .map(keystores.getCertificateChain)
    .foreach(x => println(x.length))
  keystores
    .aliases()
    .asScala
    .map(keystores.getCertificateChain)
    .foreach(x => println(x(0)))
}
