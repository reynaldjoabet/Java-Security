import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.DSAPrivateKeySpec
import java.security.spec.DSAPublicKeySpec
object KeyFactoryExample {
  val bobEncodedPubKey = Array.emptyByteArray
  val bobPubKeySpec    = new X509EncodedKeySpec(bobEncodedPubKey);
  val keyFactory       = KeyFactory.getInstance("DSA");
  val bobPubKey        = keyFactory.generatePublic(bobPubKeySpec);
  val sig              = Signature.getInstance("DSA");
  // sig.initVerify(bobPubKey);
  //  sig.update(data);
  //  sig.verify(signature);

}
