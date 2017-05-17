## 暗号化のテスト

### 鍵管理の検証

#### 概要

-- REVIEW --
ハードコードされた暗号鍵や誰でも読み取り可能な暗号鍵を使用すると、暗号化されたデータを復元される可能性が大幅に高まります。攻撃者がそれを取得すると、機密データを復号する作業は簡単になり、機密性を保護するという当初の考えは失敗します。

対称暗号を使用する場合、鍵はデバイス内に格納する必要があり、攻撃者がそれを識別するのは時間と労力の問題となります。

#### 静的解析

次のシナリオを考えます。アプリケーションは暗号化されたデータベースを読み書きしていますが、復号化はハードコードされた鍵に基づいて行われています。

```Java
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```

鍵はすべてのアプリインストールに対して同じであり取得は容易です。機密データを暗号化する利点はなくなり、そのような暗号化にはまったく意味がありません。同様に、ハードコードされた API 鍵 / 秘密鍵やその他の重要なものを探します。暗号化鍵/復号化鍵は、王冠の宝石を手に入れることは困難であるが不可能ではないという単なる試みです。

次のコードを考えてみます。

```Java
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```

この場合に元の鍵を解読するアルゴリズムは次のようになります <sup>[1]</sup> 。

```Java
public void useXorStringHiding(String myHiddenMessage) {
  byte[] xorParts0 = Base64.decode(myCompositeKey[0],0);
  byte[] xorParts1 = Base64.decode(myCompositeKey[1],0);

  byte[] xorKey = new byte[xorParts0.length];
  for(int i = 0; i < xorParts1.length; i++){
    xorKey[i] = (byte) (xorParts0[i] ^ xorParts1[i]);
  }
  HidingUtil.doHiding(myHiddenMessage.getBytes(), xorKey, false);
}
```

#### 動的解析

秘密が隠される一般的な場所を確認します。
* リソース (res/values/strings.xml が一般的)

例：
```xml
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

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- V3.5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"

##### CWE
* CWE-320: Key Management Errors
* CWE-321: Use of Hard-coded Cryptographic Key

##### その他

[1] Hiding Passwords in Android - https://github.com/pillfill/hiding-passwords-android/
[2] KeyStore - https://developer.android.com/reference/java/security/KeyStore.html
[3] Hiding Secrets in Android - https://rammic.github.io/2015/07/28/hiding-secrets-in-android-apps/
[4] Securely storing secrets in Android - https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3#.7z5yruotu

##### ツール
* [QARK](https://github.com/linkedin/qark)
* [Mobile Security Framework](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF)


### 暗号のカスタム実装に関するテスト

#### 概要

暗号機能に非標準のカスタムビルドアルゴリズムを使用することは危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性があります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。排他的 OR オペレーションなどのビットシフトオペレータが現れたら深く掘り下げてみる良い兆候かもしれません。

#### 動的解析

非常に弱い暗号の場合はカスタムアルゴリズムのファジングが機能するかもしれませんが、カスタム暗号化方式が本当に適切かどうか確認するために、APK を逆コンパイルしてアルゴリズムを調べることをお勧めします(「静的解析」を参照ください)。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。

機密データを格納する必要がある場合は強力な最新の暗号アルゴリズムを使用します。この分野の専門家により現時点で強力であると見なされている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。KeyStore は機密情報を格納するのに適しており、Android のドキュメントには提供される強力な暗号のリストがあります <sup>[1]</sup>。


#### 参考情報

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers



### 暗号化標準アルゴリズムの構成の検証

#### 概要

-- REVIEW --
適切な暗号化アルゴリズムを選択するだけでは十分ではありません。間違った構成はそれ以外の妥当なアルゴリズムのセキュリティに影響を及ぼすことがあります。過去に強力であるとされた多くのアルゴリズムや構成は、脆弱もしくはベストプラクティスに準拠していないとみなされています。したがって、最新のベストプラクティスを定期的に確認し、それに応じて構成を調整することが重要です。

#### 静的解析

-- TODO [Describe Static Analysis on Verifying the Configuration of Cryptographic Standard Algorithms : how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop Static Analysis with source code of "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

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


##### Info

-- REVIEW --
- [1] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [2] BSI recommendations (2017) - https://www.keylength.com/en/8/

##### ツール

-- TODO [Add relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify



### 安全でないもしくは廃止された暗号化アルゴリズムに関するテスト

#### 概要

多くの暗号アルゴリズムおよびプロトコルは重大な弱点があることが示されているか、現代のセキュリティ要件には不十分であるため、使用してはいけません。

#### 静的解析

アプリケーション全体で暗号アルゴリズムのインスタンスを特定するためにソースコードを調査します。
* DES
* RC2
* RC4
* BLOWFISH
* CRC32
* MD4
* MD5
* SHA1 and others.

推奨されるアルゴリズムの基本的なリストについては「改善方法」セクションを参照ください。

脆弱とみなされる DES アルゴリズムの初期化の例：
```Java
Cipher cipher = Cipher.getInstance("DES");
```

#### 動的解析

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### 改善方法

暗号化手法が廃止されていないことを定期的に確認します。以前、10億年の計算時間を要すると考えられていた一部の古いアルゴリズムは数日もしくは数時間で破られる可能性があります。これには MD4, MD5, SHA1, DES, および以前は強力であると考えられて他のアルゴリズムが含まれます。現在推奨されているアルゴリズムの例です。<sup>[1][2]</sup>

* 機密性: AES-256
* 完全性: SHA-256, SHA-384, SHA-512
* デジタル署名: RSA (3072 ビット以上), ECDSA with NIST P-384
* 鍵確立: RSA (3072 ビット以上), DH (3072 ビット以上), ECDH with NIST P-384

#### 参考情報

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
[2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
[3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF


### 乱数生成器のテスト

#### 概要

ソフトウェアが予測不可能であることを要求されるコンテキストで予測可能な値を生成する場合、攻撃者は生成される次の値を推測し、この推測を使用して別のユーザーを偽装したり機密情報にアクセスしたりする可能性があります。

#### 静的解析

乱数生成器のインスタンスをすべて特定して、カスタムまたは既知の安全でない java.util.Random クラスを探します。このクラスは与えられた各シード値に対して同じ一連の番号を生成します。その結果、一連の数は予測可能となります。
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

#### 動的解析

攻撃者がどのようなタイプの脆弱な疑似乱数生成器 (PRNG) が使用されているかを知ることで、Java Random <sup>[1]</sup> で行われたように、以前に観測された値に基づいて次の乱数値を生成する概念実証を書くことは簡単です。非常に脆弱なカスタム乱数生成器の場合にはパターンを統計的に観測することが可能かもしれません。推奨される方法はとにかく APK を逆コンパイルしてアルゴリズムを検査することです(「静的解析」を参照ください)。

#### 改善方法

この分野の専門家により強力であると現在考えられている十分に検証されたアルゴリズムを使用して、適切な長さのシードを持つ十分にテストされた実装を選択します。システム固有のシード値を使用して128バイト乱数を生成する SecureRandom の引数なしコンストラクタを推奨します <sup>[2]</sup> 。
一般に、PRNG が暗号的にセキュアであると宣言されていない場合(java.util.Random など)、それはおそらく統計的 PRNG であり、セキュリティ機密のコンテキストでは使用すべきではありません。
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
[1] Predicting the next Math.random() in Java - http://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/
[2] Generation of Strong Random Numbers - https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers
[3] Proper seeding of SecureRandom - https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded

##### ツール
* QARK - https://github.com/linkedin/qark
