package com.eshare.security.utils;

import static org.junit.Assert.*;

import io.jsonwebtoken.lang.Assert;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.util.UUID;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Test;
import sun.security.tools.KeyStoreUtil;

/**
 * Created by liangyh on 2019/8/25. Email:10856214@163.com
 */
public class KeyConvertUtilTest {

  public static final String ID = "123";
  public static final String PASSWORD = "123456";

  public static final String PUBLIC_KEY_FILE = "pub.asc";
  public static final String PRIVATE_KEY_FILE = "secret.asc";

  /**
   * Key store file name
   * <p>
   * keytool -genkey -alias mykey20201231 -keyalg RSA -validity 145 -keystore mycompany.keystore
   * -storetype JKS -storepass 123456
   *
   * keytool -importkeystore -srckeystore mycompany.keystore -srcstorepass 123456 -srckeypass 123456
   * -srcalias mykey20201231 -destalias mykey20201231 -destkeystore mycompany.p12 -deststoretype
   * PKCS12 -deststorepass 1234546 -destkeypass 123456
   *
   *
   * keytool -export -alias mykey20201231 -keystore mycompany.keystore -file myKeyAliasInBank.cer -storepass 123456
   * //import public key
   * keytool -import -alias test -file myKeyAliasInBank.cer -keystore mycompany.keystore -storepass 123456
   * </p>
   */
  public static final String KEYSTORE_FILE = "mycompany.keystore";

  public static final String PRIVATE_KEY_ALIAS = "mykey20201231";


  /**
   * used to fix java.security.NoSuchProviderException: no such provider: BC
   */
  static {
    try {
      Security.addProvider(new BouncyCastleProvider());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testConvertPGPPublicKey2PublicKey() throws IOException, PGPException {
    PGPPublicKey pgpPublicKey = PGPKeyUtil.readPublicKey(findFile(PUBLIC_KEY_FILE));
    PublicKey publicKey = KeyConvertUtil.convertPGPPublicKey2PublicKey(pgpPublicKey);
    //Check if the public key is an instance of RSAKey
    Assert.isInstanceOf(RSAKey.class, publicKey);

  }

  @Test
  public void tsetConvertPGPPrivateKey2PrivateKey()
      throws IOException, PGPException, NoSuchProviderException {
    PGPSecretKey pgpSecretKey = PGPKeyUtil.readSecretKey(findFile(PRIVATE_KEY_FILE));
    //Prepare key ring collection
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(findFile(PRIVATE_KEY_FILE)), new JcaKeyFingerprintCalculator());
    final PGPPrivateKey pgpPrivateKey = PGPKeyUtil
        .findSecretKey(pgpSec, pgpSecretKey.getKeyID(), PASSWORD.toCharArray());
    PrivateKey privateKey = KeyConvertUtil.convertPGPPrivateKey2PrivateKey(pgpPrivateKey);
    //Check if the private key is an instance of RSAKey
    Assert.isInstanceOf(RSAKey.class, privateKey);
  }

  @Test
  public void testGetKeypair()
      throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
    KeyStore instance = KeyStore.getInstance(KeyStore.getDefaultType());
    instance.load(findFile(KEYSTORE_FILE), PASSWORD.toCharArray());
    KeyPair keyPair = KeyConvertUtil.getKeyPair(instance, PRIVATE_KEY_ALIAS, PASSWORD);
    //Check if the private key is an instance of Key
    Assert.isInstanceOf(RSAKey.class, keyPair.getPrivate());

  }


  private static InputStream findFile(final String file) {
    return KeyConvertUtilTest.class.getClassLoader().getResourceAsStream(file);
  }
}