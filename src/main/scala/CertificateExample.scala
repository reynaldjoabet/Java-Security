import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.util.Base64

import javax.crypto.spec.DHPublicKeySpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

object CertificateExample extends App {

  val url            = "https://www.baeldung.com"
  val destinationUrl = new URL(url)

  val conn = destinationUrl.openConnection().asInstanceOf[HttpURLConnection]

  // conn.connect()

  // val certs= conn.getResponseMessage()

  val ks       = KeyStore.getInstance(KeyStore.getDefaultType())
  val password = "changeit"
  // To create an empty keystore using the above  load method,
  // pass null as the InputStream argument.
  ks.load(null, password.toCharArray())

  val protParam = new KeyStore.PasswordProtection(password.toCharArray())
// get my private key
// val pkEntry =ks.getEntry("privateKeyAlias", protParam).asInstanceOf[KeyStore.PrivateKeyEntry]
// val myPrivateKey = pkEntry.getPrivateKey();
// save my secret key
// var mySecretKey:SecretKey= null
//     val skEntry =new KeyStore.SecretKeyEntry(mySecretKey)
//     ks.setEntry("secretKeyAlias", skEntry, protParam)

//The secret key is derived from a given password using a password-based key derivation function like PBKDF2. We also need a salt value for turning a password into a secret key. The salt is also a random value.
//We can use the SecretKeyFactory class with the PBKDF2WithHmacSHA256 algorithm for generating a key from a given password.
//Let’s define a method for generating the SecretKey from a given password with 65,536 iterations and a key length of 256 bits:

//PBKDF2WithHmacSHA224
// PBKDF2WithHmacSHA256
// PBKDF2WithHmacSHA384
// PBKDF2WithHmacSHA512

  def getKeyFromPassword256(password: String, salt: String) = {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec =
      new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
    val originalKey =
      new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    originalKey
  }

  def getKeyFromPassword384(password: String, salt: String) = {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384")
    val spec =
      new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
    val originalKey =
      new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    originalKey
  }

  def getKeyFromPassword512(password: String, salt: String) = {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
    val spec =
      new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
    val originalKey =
      new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    originalKey
  }

  val spec    = getKeyFromPassword256("hello", "dude33434343")
  val rawData = spec.getEncoded()

  val spec1    = getKeyFromPassword256("hello", "dude33434343")
  val rawData1 = spec1.getEncoded()

  val encodedKey = Base64.getEncoder().encodeToString(rawData)

  val encodedKey1 = Base64.getEncoder().encodeToString(rawData1)
  println(spec)

  println(spec1)
  println(encodedKey)

  println(encodedKey1)

  val spec384    = getKeyFromPassword384("hello", "dude33434343")
  val rawData384 = spec384.getEncoded()

  val spec512     = getKeyFromPassword512("hello", "dude33434343")
  val rawData521  = spec512.getEncoded()
  val spec5121    = getKeyFromPassword512("hello", "dude33434343")
  val rawData5211 = spec5121.getEncoded()

  val encodedKey384 = Base64.getEncoder().encodeToString(rawData384)

  val encodedKey521 = Base64.getEncoder().encodeToString(rawData521)

  val encodedKey5211 = Base64.getEncoder().encodeToString(rawData5211)
  println(encodedKey384)

  println(encodedKey521)
  println(encodedKey5211)

}
