package com.eshare.security.utils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.eshare.security.common.AbstractTest;
import java.io.IOException;
import java.security.NoSuchProviderException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.Test;

/**
 * Created by liangyh on 2019/8/25. Email:10856214@163.com
 */
public class PGPKeyUtilTest extends AbstractTest {


  @Test
  public void compressFile() {
  }

  @Test
  public void findSecretKey() throws IOException, PGPException, NoSuchProviderException {
    PGPSecretKey pgpSecretKey = PGPKeyUtil.readSecretKey(findFile(PRIVATE_KEY_FILE));
    //Prepare key ring collection
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(findFile(PRIVATE_KEY_FILE)), new JcaKeyFingerprintCalculator());
    assertNotNull(PGPKeyUtil.findSecretKey(pgpSec,pgpSecretKey.getKeyID(),PASSWORD.toCharArray()));

  }

  @Test
  public void readPublicKey() throws IOException, PGPException {
    assertTrue(PGPKeyUtil.readPublicKey(findFile(PUBLIC_KEY_FILE)).isEncryptionKey());
  }


  @Test
  public void readSecretKey() throws IOException, PGPException {
    assertTrue(PGPKeyUtil.readSecretKey(findFile(PRIVATE_KEY_FILE)).isSigningKey());
  }

}