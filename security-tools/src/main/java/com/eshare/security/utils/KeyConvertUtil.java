package com.eshare.security.utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

/**
 * Key Utils Created by liangyh on 2019/8/25. Email:10856214@163.com
 */
public class KeyConvertUtil {

  /**
   * Convert a pgp public key to public key
   *
   * @param pgpPublicKey pgp public key
   * @return PublicKey a public key implemented from Key
   * @throws PGPException generic exception class for PGP encoding/decoding problems
   */
  public static PublicKey convertPGPPublicKey2PublicKey(PGPPublicKey pgpPublicKey)
      throws PGPException {
    return new JcaPGPKeyConverter().getPublicKey(pgpPublicKey);
  }

  /**
   * Convert a pgp private key to private key
   *
   * @param pgpPrivateKey pgp private key
   * @return PrivateKey a private key implemented from Key
   * @throws PGPException generic exception class for PGP encoding/decoding problems
   */
  public static PrivateKey convertPGPPrivateKey2PrivateKey(PGPPrivateKey pgpPrivateKey)
      throws PGPException {
    return new JcaPGPKeyConverter().getPrivateKey(pgpPrivateKey);
  }

}
