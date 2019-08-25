package com.eshare.security.utils;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
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

  /**
   * Get keypair from keystore file
   * @param keyStore keystore file object
   * @param alias key alias used to find te corresponding key
   * @param password key password for the key
   * @return the keypair
   * @throws UnrecoverableKeyException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   */
  public static KeyPair getKeyPair(final KeyStore keyStore, final String alias,
      final String password)
      throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    final Key key = keyStore.getKey(alias, password.toCharArray());
    final Certificate cert = keyStore.getCertificate(alias);
    final PublicKey publicKey = cert.getPublicKey();
    return new KeyPair(publicKey, (PrivateKey) key);
  }

}
