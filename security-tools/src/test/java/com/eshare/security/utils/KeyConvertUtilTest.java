package com.eshare.security.utils;

import static org.junit.Assert.*;

import io.jsonwebtoken.lang.Assert;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.UUID;
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
public class KeyConvertUtilTest {

  public static final String ID = "123";
  public static final String PASSWORD = "123456";

  public static final String PUBLIC_KEY_FILE = "pub.asc";
  public static final String PRIVATE_KEY_FILE = "secret.asc";


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
  public void convertPGPPublicKey2PublicKey() throws IOException, PGPException {
    PGPPublicKey pgpPublicKey = PGPKeyUtil.readPublicKey(findFile(PUBLIC_KEY_FILE));
    PublicKey publicKey = KeyConvertUtil.convertPGPPublicKey2PublicKey(pgpPublicKey);
    //Check if the public key is an instance of Key
    Assert.isInstanceOf(Key.class, publicKey);

  }

  @Test
  public void convertPGPPrivateKey2PrivateKey()
      throws IOException, PGPException, NoSuchProviderException {
    PGPSecretKey pgpSecretKey = PGPKeyUtil.readSecretKey(findFile(PRIVATE_KEY_FILE));
    //Prepare key ring collection
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(findFile(PRIVATE_KEY_FILE)), new JcaKeyFingerprintCalculator());
    final PGPPrivateKey pgpPrivateKey = PGPKeyUtil
        .findSecretKey(pgpSec, pgpSecretKey.getKeyID(), PASSWORD.toCharArray());
    PrivateKey privateKey = KeyConvertUtil.convertPGPPrivateKey2PrivateKey(pgpPrivateKey);
    //Check if the private key is an instance of Key
    Assert.isInstanceOf(Key.class, privateKey);
  }

  private static InputStream findFile(final String file) {
    return KeyConvertUtilTest.class.getClassLoader().getResourceAsStream(file);
  }
}