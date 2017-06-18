## 暗号化のテスト (Android アプリ)

### 暗号化標準アルゴリズムの構成の検証

#### 概要

アプリ開発の一般的なルールは自分自身の暗号を発明しようとすべきではないということです。特にモバイルアプリでは、あらゆる形式の暗号は既存の堅牢な実装を使用して実装されるべきです。99% のケースでは、モバイル OS に付属のデータストレージ API と暗号化ライブラリを使用するだけです。

Android cryptography APIs are based on the Java Cryptography Architecture (JCA). JCA separates the interfaces and implementation, making it possible to include several cryptographic service providers that can implement sets of cryptographic algorithms. Most of the JCA interfaces and classes are defined in the `java.security.*` and `javax.crypto.*` packages. In addition, there are Android specific packages `android.security.*` and `android.security.keystore.*`.

The list of providers included in Android varies between versions of Android and the OEM-specific builds. Some provider implementations in older versions are now known to be less secure or vulnerable. Thus, Android applications should not only choose the correct algorithms and provide good configuration, in some cases they should also pay attention to the strength of the implementations in the legacy providers.

For some applications that support older versions of Android, bundling an up-to-date library may be the only option. SpongyCastle (a repackaged version of BouncyCastle) is a common choice in these situations. Repackaging is necessary because BouncyCastle is included in the Android SDK. The latest version of SpongyCastle likely fixes issues encountered in the earlier versions of BouncyCastle that were included in older versions of Android.

Android SDK provides mechanisms for specifying secure key generation and use. Android 6.0 (Marshmallow, API 23) introduced the `KeyGenParameterSpec` class that can be used to ensure the correct key usage in the application. 

Here's an example of using AES/CBC/PKCS7Padding on API 23+:

```
String keyAlias = "MySecretKey";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setRandomizedEncryptionRequired(true)
        .build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore");
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

The `KeyGenParameterSpec` indicates that the key can be used for encryption and decryption, but not for other purposes, such as signing or verifying. It further specifies the block mode (CBC), padding (PKCS7), and explicitly specifies that randomized encryption is required (this is the default.) `"AndroidKeyStore"` is the name of the cryptographic service provider used in this example.

GCM is another AES block mode that provides additional security benefits over other, older modes. In addition to being cryptographically more secure, it also provides authentication. When using CBC (and other modes), authentication would need to be performed separately, using HMACs (see the Reverse Engineering chapter). Note that GCM is the only mode of AES that does not support paddings.<sup>[3], [5]</sup>

Attempting to use the generated key in violation of the above spec would result in a security exception.

Here's an example of using that key to decrypt:

```
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_CBC
        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = keyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the iv and the encryptedBytes
```

Both the IV and the encrypted bytes need to be stored; otherwise decryption is not possible.

Here's how that cipher text would be decrypted. The `input` is the encrypted byte array and `iv` is the initialization vector from the encryption step:

```
// byte[] input
// byte[] iv
Key key = keyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

Since the IV (initialization vector) is randomly generated each time, it should be saved along with the cipher text (`encryptedBytes`) in order to decrypt it later.

Prior to Android 6.0, AES key generation was not supported. As a result, many implementations chose to use RSA and generated public-private key pair for asymmetric encryption using `KeyPairGeneratorSpec` or used `SecureRandom` to generate AES keys.

Here's an example of `KeyPairGenerator` and `KeyPairGeneratorSpec` used to create the RSA key pair:

```Java
Date startDate = Calendar.getInstance().getTime();
Calendar endCalendar = Calendar.getInstance();
endCalendar.add(Calendar.YEAR, 1);
Date endDate = endCalendar.getTime();
KeyPairGeneratorSpec keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
        .setAlias(RSA_KEY_ALIAS)
        .setKeySize(4096)
        .setSubject(new X500Principal("CN=" + RSA_KEY_ALIAS))
        .setSerialNumber(BigInteger.ONE)
        .setStartDate(startDate)
        .setEndDate(endDate)
        .build();

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        "AndroidKeyStore");
keyPairGenerator.initialize(keyPairGeneratorSpec);

KeyPair keyPair = keyPairGenerator.generateKeyPair();

```

This sample creates the RSA key pair with the 4096-bit key (i.e., modulus size).


-- TODO Add the pre-Marshmallow AES example using BC --




#### 静的解析

Locate uses of the cryptographic primitives in code. Some of the most frequently used classes and interfaces:

* `Cipher`
* `Mac`
* `MessageDigest`
* `Signature`
* `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
* And a few others in the `java.security.*` and `javax.crypto.*` packages.

Ensure that the best practices outlined in the Cryptography for Mobile Apps chapter are followed.

#### 改善方法

See the Remediation section in the Cryptography for Mobile Apps chapter.

-- REVIEW --

NIST <sup>1</sup> や BSI <sup>2</sup> 推奨のような現在強力であると考えられている暗号アルゴリズム構成を使用します。


#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

-- REVIEW --

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- REVIEW --

* CWE-326: Inadequate Encryption Strength


##### その他

-- REVIEW --

- [1] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [2] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [3] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers
- [4] Credential storage enhancements in Android 4.3 (August 21, 2013) - https://nelenkov.blogspot.co.uk/2013/08/credential-storage-enhancements-android-43.html
- [5] Cipher documentation - https://developer.android.com/reference/javax/crypto/Cipher.html


### 乱数生成器のテスト

#### 概要

Cryptography requires secure pseudo random number generation (PRNG). Standard Java classes do not provide sufficient randomness and in fact may make it possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

In general, `SecureRandom` should be used. However, if the Android versions below KitKat are supported, additional care needs to be taken in order to work around the bug in Jelly Bean (Android 4.1-4.3) versions that failed to properly initialize the PRNG<sup>[4]</sup>.

Most developers should instantiate `SecureRandom` via the default constructor without any arguments. Other constructors are for more advanced uses and, if used incorrectly, can lead to decreased randomness and security. The PRNG provider backing `SecureRandom` uses the `/dev/urandom` device file as the source of randomness by default.<sup>[5]</sup>

#### 静的解析

乱数生成器のインスタンスをすべて特定して、カスタムまたは既知の安全でない `java.util.Random` クラスを探します。このクラスは与えられた各シード値に対して同じ一連の番号を生成します。その結果、一連の数は予測可能となります。
以下のサンプルソースコードは脆弱な乱数生成器を示しています。

```Java
import java.util.Random;
// ...

Random number = new Random(123L);
//...
for (int i = 0; i < 20; i++) {
  // Generate another random integer in the range [0, 20]
  int n = number.nextInt(21);
  System.out.println(n);
}
```

Identify all instances of `SecureRandom` that are not created using the default constructor. Specifying the seed value may reduce randomness.

#### 動的解析

攻撃者がどのようなタイプの脆弱な疑似乱数生成器 (PRNG) が使用されているかを知ることで、Java Random <sup>[1]</sup> で行われたように、以前に観測された値に基づいて次の乱数値を生成する概念実証を書くことは簡単です。非常に脆弱なカスタム乱数生成器の場合にはパターンを統計的に観測することが可能かもしれません。推奨される方法はとにかく APK を逆コンパイルしてアルゴリズムを検査することです(「静的解析」を参照ください)。

#### 改善方法

この分野の専門家により強力であると現在考えられている十分に検証されたアルゴリズムを使用して、適切な長さのシードを持つ十分にテストされた実装を選択します。システム固有のシード値を使用して128バイト乱数を生成する `SecureRandom` の引数なしコンストラクタを推奨します <sup>[2]</sup> 。
一般に、PRNG が暗号的にセキュアであると宣言されていない場合 (`java.util.Random` など) 、それはおそらく統計的 PRNG であり、セキュリティ機密のコンテキストでは使用すべきではありません。
疑似乱数生成器は生成器が既知でありシードが推測できる場合には予測可能な数値を生成します <sup>[3]</sup> 。128ビットシードは「十分にランダムな」数を生成するための良い出発点です。

以下のサンプルソースコードはセキュアな乱数生成を示しています。

```Java
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
// ...

public static void main (String args[]) {
  SecureRandom number = new SecureRandom();
  // Generate 20 integers 0..20
  for (int i = 0; i < 20; i++) {
    System.out.println(number.nextInt(21));
  }
}
```

#### 参考情報

##### OWASP MASVS
- V3.6: "すべての乱数値は、十分に安全な乱数生成器を用いて生成している。"

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### CWE
* CWE-330: Use of Insufficiently Random Values

##### その他
- [1] Predicting the next Math.random() in Java - http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/
- [2] Generation of Strong Random Numbers - https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers
- [3] Proper seeding of SecureRandom - https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded
- [4] Some SecureRandom Thoughts - https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html
- [5] N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.
