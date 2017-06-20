## 暗号化のテスト (Android アプリ)

### 暗号化標準アルゴリズムの構成の検証

#### 概要

アプリ開発の一般的なルールは自分自身の暗号を発明しようとすべきではないということです。特にモバイルアプリでは、あらゆる形式の暗号は既存の堅牢な実装を使用して実装されるべきです。99% のケースでは、モバイル OS に付属のデータストレージ API と暗号化ライブラリを使用するだけです。

Android 暗号化 API は Java Cryptography Architecture (JCA) に基づいています。JCA はインタフェースと実装を分離し、一連の暗号アルゴリズムを実装できる複数の暗号化サービスプロバイダを含めることができます。ほとんどの JCA インタフェースとクラスは `java.security.*` および `javax.crypto.*` パッケージで定義されています。さらに、Android 固有のパッケージ `android.security.*` および `android.security.keystore.*` もあります。

Android に含まれるプロバイダのリストは Android のバージョンと OEM 固有のビルドにより異なります。一部の古いバージョンのプロバイダ実装は安全性が低く脆弱であることが知られています。したがって、Android アプリケーションは正しいアルゴリズムを選択して適切な設定を行うだけでなく、場合によっては従来のプロバイダの実装の強度にも注意を払う必要があります。

古いバージョンの Android をサポートする一部のアプリケーションでは、最新のライブラリをバンドルすることが唯一の選択肢かもしれません。SpongyCastle (BouncyCastle の再パッケージ版) はこれらの状況では一般的な選択肢です。BouncyCastle は Android SDK に含まれているため、再パッケージ化が必要です。SpongyCastle の最新バージョンでは古いバージョンの Android に含まれていた旧バージョンの BouncyCastle で発生した問題が修正されている可能性があります。

Android SDK はセキュアな鍵生成および使用を記述するためのメカニズムを提供します。Android 6.0 (Marshmallow, API 23) ではアプリケーションで正しい鍵の使用を保証するために使用できる `KeyGenParameterSpec` クラスを導入しました。

API 23 以降での AES/CBC/PKCS7Padding の使用例を以下に示します。

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

`KeyGenParameterSpec` は鍵を暗号化および復号化に使用できることを示しますが、署名や検証などの他の目的は示しません。さらに、ブロックモード (CBC)、パディング (PKCS7) を指定し、ランダム化された暗号化が必要であることを明示します (これがデフォルトです) 。`"AndroidKeyStore"` はこの例で使用される暗号化サービスプロバイダの名前です。

GCM はもうひとつの AES ブロックモードであり、他の古いモードよりもセキュリティ上の利点があります。暗号的によりセキュアであることに加えて、認証も提供します。CBC (および他のモード) を使用する場合は、認証は HMAC を使用して別に実行する必要があります (リバースエンジニアリングの章を参照ください) 。GCM はパディングをサポートしない AES の唯一のモードであることに注意します。 <sup>[3], [5]</sup>

上記の仕様に違反して生成された鍵の使用を試みるとセキュリティ例外が発生します。

その鍵を使用して復号する例を以下に示します。

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

IV および暗号化されたバイト列の双方を格納する必要があります。さもなければ解読は不可能です。

暗号文を解読する方法を以下に示します。`input` は暗号化されたバイト配列であり、`iv` は暗号スペックの初期化ベクトルです。

```
// byte[] input
// byte[] iv
Key key = keyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

IV (初期化ベクトル) は毎回ランダムに生成されるため、後で解読するために暗号文 (`encryptedBytes`) とともに保存する必要があります。

Android 6.0 以前は、AES 鍵の生成はサポートされていませんでした。結果として、多くの実装では RSA を使用することを選択し、`KeyPairGeneratorSpec` を使用して非対称暗号化の公開鍵と秘密鍵のペアを生成しました。あるいは `SecureRandom` を使用して AES 鍵を生成しました。

RSA 鍵ペアの作成に使用される `KeyPairGenerator` および `KeyPairGeneratorSpec` の例を以下の示します。

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

この例では 4096 ビットの鍵 (すなわち、モジュラスサイズ) を持つ RSA 鍵のペアを作成します。


-- TODO Add the pre-Marshmallow AES example using BC --




#### 静的解析

コード内の暗号化プリミティブの使用箇所を見つけます。最もよく使用されるクラスとインタフェースのいくつかを以下に示します。

* `Cipher`
* `Mac`
* `MessageDigest`
* `Signature`
* `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
* `java.security.*` および `javax.crypto.*` パッケージにあるその他のもの

「モバイルアプリでの暗号化」の章に記載されているベストプラクティスに従っていることを確かめます。

#### 改善方法

「モバイルアプリでの暗号化」の章の「改善方法」セクションを参照します。

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
