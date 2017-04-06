## 暗号化のテスト

### 鍵管理の検証

#### 概要

ハードコードされた暗号鍵や誰でも読み取り可能な暗号鍵を使用すると、暗号化されたデータを復元される可能性が大幅に高まります。

-- TODO [Develop overview on Verifying Key Management]

#### ホワイトボックステスト

次のシナリオを考えます。アプリケーションは暗号化されたデータベースを読み書きしていますが、復号化はハードコードされた鍵に基づいて行われています。
```
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```
鍵はすべてのユーザーに対して同じであり取得は容易であるため、機密データを暗号化する利点はなくなり、そのような暗号化にはまったく意味がありません。同様に、ハードコードされた API 鍵 / 秘密鍵やその他の重要なものを探します。暗号化鍵/復号化鍵は、王冠の宝石を手に入れることは困難であるが不可能ではないという単なる試みです。

次のコードを考えてみます。
```
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```
この場合に元の鍵を解読するアルゴリズムは次のようになります <sup>[1]</sup> 。
```
public void useXorStringHiding(String myHiddenMessage) {
  byte[] xorParts0 = Base64.decode(myCompositeKey[0],0);
  byte[] xorParts1 = Base64.decode(myCompositeKey[1], 0);

  byte[] xorKey = new byte[xorParts0.length];
  for(int i = 0; i < xorParts1.length; i++){
    xorKey[i] = (byte) (xorParts0[i] ^ xorParts1[i]);
  }
  HidingUtil.doHiding(myHiddenMessage.getBytes(), xorKey, false);
}
```

#### ブラックボックステスト

秘密が隠される一般的な場所を確認します。
* リソース (res/values/strings.xml が一般的)

例：
```
<resources>
    <string name="app_name">SuperApp</string>
    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>
    <string name="secret_key">My_S3cr3t_K3Y</string>
  </resources>
```

* ビルド設定、local.properties や gradle.properties など

例：
```
buildTypes {
  debug {
    minifyEnabled true
    buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
  }
}
```

* 共有プリファレンス、/data/data/package_name/shared_prefs が一般的


#### 改善方法

繰り返し使用するために鍵を格納する必要がある場合は、暗号鍵の長期保存や取り出しの仕組みを提供する KeyStore <sup>[2]</sup> などの機構を使用します。

#### 参考情報
* [1]: https://github.com/pillfill/hiding-passwords-android/
* [2]: https://developer.android.com/reference/java/security/KeyStore.html

##### OWASP MASVS
- V3.1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- V3.5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"
- V3.7: "All cryptographic keys are changeable, and are generated or replaced at installation time"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-320: Key Management Errors
* CWE-321: Use of Hard-coded Cryptographic Key

##### その他

* https://rammic.github.io/2015/07/28/hiding-secrets-in-android-apps/
* https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3#.7z5yruotu


##### ツール
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)


### 暗号のカスタム実装に関するテスト

#### 概要

The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm and compromise whatever data has been protected. Well-known techniques may exist to break the algorithm.

#### ホワイトボックステスト

Carefully inspect all the crypto methods, especially those which are directly applied to the sensitive data. Pay close attention to seemingly standard but modified algorithms. Remember that encoding is not encryption! Any appearance of direct XORing might be a good sign to start digging deeper.

#### ブラックボックステスト

Although fuzzing of the custom algorithm might work in case of very weak crypto, the recommended approach would be to decompile the APK and inspect the algorithm to see if custom encryption schemes is really the case (see "White-box Testing")

#### 改善方法

When there is a need to store or transmit sensitive data, use strong, up-to-date cryptographic algorithms to encrypt that data. Select a well-vetted algorithm that is currently considered to be strong by experts in the field, and use well-tested implementations. As with all cryptographic mechanisms, the source code should be available for analysis.
Do not develop custom or private cryptographic algorithms. They will likely be exposed to attacks that are well-understood by cryptographers. Reverse engineering techniques are mature. If the algorithm can be compromised if attackers find out how it works, then it is especially weak.

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### 暗号化標準アルゴリズムの構成の検証

#### 概要

-- TODO [Provide a general description of the issue "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### 静的解析

-- TODO [Describe Static Analysis on Verifying the Configuration of Cryptographic Standard Algorithms : how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Develop Static Analysis with source code of "Verifying the Configuration of Cryptographic Standard Algorithms"] --

##### ソースコードなし

-- TODO [Develop Static Analysis without source code of "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying the Configuration of Cryptographic Standard Algorithms".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" to OWASP MASVS] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify


### 安全でないもしくは廃止された暗号化アルゴリズムに関するテスト

#### 概要

Many cryptographic algorithms and protocols should not be used because they have been shown to have significant weaknesses or are otherwise insufficient for modern security requirements.

#### ホワイトボックステスト

Inspect the code to identify the instances of crypto algorithms throughout the application, and look for known weak ones, such as DES, RC2, CRC32, MD4, MD5, SHA1 and others. See "Remediation" section for a basic list of recommended algorithms.

Example of initialization of DES algorithm:
```
Cipher cipher = Cipher.getInstance("DES");
```

#### ブラックボックステスト

Decompile the APK and inspect the code to see if known weak crypto algorithms are in place (see "White-box Testing")

-- TODO [Give examples of black-box testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### 改善方法

Periodically ensure that the cryptography has not become obsolete. Some older algorithms, once thought to require a billion years of computing time, can now be broken in days or hours. This includes MD4, MD5, SHA1, DES, and other algorithms that were once regarded as strong. Examples of currently recommended algorithms<sup>[1][2]</sup>:

* Confidentiality: AES-256
* Integrity: SHA-256, SHA-384, SHA-512
* Digital signature: RSA (3072 bits and higher), ECDSA with NIST P-384
* Key establishment: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384


#### 参考情報

* [1]: [Commercial National Security Algorithm Suite and Quantum Computing FAQ](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf)
* [2]: [NIST Special Publication 800-57](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf)

##### OWASP MASVS
- V3.3: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated"
- V3.4: "Cryptographic modules use parameters that adhere to current industry best practices. This includes key length and modes of operation"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他

* https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html

##### ツール
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)


### 乱数生成器のテスト

#### 概要

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

#### ホワイトボックステスト

Identify all the instances of random number generators and look for either custom or known insecure java.util.Random class. This class produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable.
Sample weak random generation code:

```
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

#### ブラックボックステスト

Knowing what type of weak PRNG is used, it can be trivial to write proof-of-concept to generate next random value based on previously observed ones, as it was done for Java Random<sup>[1]</sup>. In case of very weak custom random generators it may be possible to observe the pattern statistically, although the recommended approach would anyway be to decompile the APK and inspect the algorithm (see "White-box Testing")

#### 改善方法

Use a well-vetted algorithm that is currently considered to be strong by experts in the field, and select well-tested implementations with adequate length seeds. Prefer the no-argument constructor of SecureRandom that uses the system-specified seed value to generate a 128-byte-long random number<sup>[2]</sup>.
In general, if a pseudo-random number generator is not advertised as being cryptographically secure (e.g. java.util.Random), then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
Pseudo-random number generators can produce predictable numbers if the generator is known and the seed can be guessed<sup>[3]</sup>. A 128-bit seed is a good starting point for producing a "random enough" number.

Sample secure random generation:

```
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

* [1]: [Predicting the next Math.random() in Java](http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/)
* [2]: [Generation of Strong Random Numbers](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers)
* [3]: [Proper seeding of SecureRandom](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded)

##### OWASP MASVS

- V3.6: "すべての乱数値は、十分に安全な乱数生成器を用いて生成している。"

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### CWE

* CWE-330: Use of Insufficiently Random Values

##### ツール

* [QARK](https://github.com/linkedin/qark)
