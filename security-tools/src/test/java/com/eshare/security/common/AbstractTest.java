package com.eshare.security.common;

import com.eshare.security.utils.KeyConvertUtilTest;
import java.io.InputStream;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Created by liangyh on 2019/8/25. Email:10856214@163.com
 */
public class AbstractTest {

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
   * keytool -export -alias mykey20201231 -keystore mycompany.keystore -file myKeyAliasInBank.cer
   * -storepass 123456 //import public key keytool -import -alias test -file myKeyAliasInBank.cer
   * -keystore mycompany.keystore -storepass 123456
   * </p>
   */
  public static final String KEYSTORE_FILE = "mycompany.keystore";

  public static final String KEY_ALIAS = "mykey20201231";

  protected static InputStream findFile(final String file) {
    return KeyConvertUtilTest.class.getClassLoader().getResourceAsStream(file);
  }

}
