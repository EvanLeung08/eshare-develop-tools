package com.eshare.security.utils;

import com.eshare.security.common.AbstractTest;
import io.jsonwebtoken.lang.Assert;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Test;

/**
 * Created by liangyh on 2019/8/25. Email:10856214@163.com
 */
public class KeyConvertUtilTest extends AbstractTest {


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
    KeyPair keyPair = KeyConvertUtil.getKeyPair(instance, KEY_ALIAS, PASSWORD);
    //Check if the private key is an instance of Key
    Assert.isInstanceOf(RSAKey.class, keyPair.getPrivate());

  }

}