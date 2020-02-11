## Android の暗号化 API

「[モバイルアプリの暗号化](0x04g-Testing-Cryptography.md)」の章では、一般的な暗号のベストプラクティスを紹介し、モバイルアプリで暗号が間違って使用される場合に起こりうる典型的な欠陥について説明しました。この章では、Android の暗号化 API について詳しく説明します。ソースコード内でのこれらの API の使用をどのように識別し、構成をどのように解釈するかを示します。コードをレビューする際には、このガイドからリンクされている最新のベストプラクティスで使用されている暗号パラメータを必ず比較します。

### 暗号標準アルゴリズムの構成の検討 (MSTG-CRYPTO-2, MSTG-CRYPTO-3 および MSTG-CRYPTO-4)

#### 概要

Android 暗号化 API は Java Cryptography Architecture (JCA) に基づいています。JCA はインタフェースと実装を分離し、一連の暗号アルゴリズムを実装できる複数の [セキュリティプロバイダ](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") を組み込むことができます。ほとんどの JCA インタフェースとクラスは `java.security.*` および `javax.crypto.*` パッケージで定義されています。さらに、Android 固有のパッケージ `android.security.*` および `android.security.keystore.*` もあります。

Android に含まれるプロバイダのリストは Android のバージョンと OEM 固有のビルドにより異なります。一部の古いバージョンのプロバイダ実装は安全性が低く脆弱であることが知られています。したがって、Android アプリケーションは正しいアルゴリズムを選択して適切な設定を行うだけでなく、場合によっては過去のプロバイダの実装の強度にも注意を払う必要があります。

既存のプロバイダのセットは以下のように一覧表示できます。

```java
StringBuilder builder = new StringBuilder();
for (Provider provider : Security.getProviders()) {
    builder.append("provider: ")
            .append(provider.getName())
            .append(" ")
            .append(provider.getVersion())
            .append("(")
            .append(provider.getInfo())
            .append(")\n");
}
String providers = builder.toString();
//now display the string on the screen or in the logs for debugging.
```

以下は、セキュリティプロバイダにパッチを当てた後、Google Play API を搭載したエミュレータで実行中の Android 4.4 (API level 19) の出力です。

```text
provider: GmsCore_OpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: AndroidOpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: DRLCertFactory1.0 (ASN.1, DER, PkiPath, PKCS7)
provider: BC1.49 (BouncyCastle Security Provider v1.49)
provider: Crypto1.0 (HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature))
provider: HarmonyJSSE1.0 (Harmony JSSE Provider)
provider: AndroidKeyStore1.0 (Android AndroidKeyStore security provider)
```

古いバージョンの Android (例: Android 7.0 (API level 24) より以前のバージョンのみ使用) をサポートする一部のアプリケーションでは、最新のライブラリをバンドルすることが唯一の選択肢かもしれません。Spongy Castle (Bouncy Castle の再パッケージ版) はこのような状況では一般的な選択肢です。Bouncy Castle は Android SDK に含まれているため、再パッケージ化が必要です。[Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") の最新バージョンではAndroid に含まれていた旧バージョンの [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") で発生した問題が修正されている可能性があります。Android にパックされた Bouncy Castle ライブラリは [多くの Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java") の対応ほど完全ではないことがよくあることに注意します。最後に、Spongy Castle のような大きなライブラリをパックすることは、しばしばマルチ dex 化 Android アプリケーションにつながることを心に留めておきます。

最新の API レベルを対象としたアプリは以下の変更を検討します。

- Android 7.0 (API level 24) 以上では [Android 開発者ブログは以下のように記されています](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Andorid N") 。
  - セキュリティプロバイダの指定を停止することを推奨します。代わりに、常にパッチされたセキュリティプロバイダを使用します。
  - `Crypto` プロバイダのサポートは中止されており、このプロバイダは非推奨です。
  - 安全なランダムのための `SHA1PRNG` のサポートはもはやありませんが、代わりにそのランタイムは `OpenSSLRandom` のインスタンスを提供します。
- Android 8.1 (API level 27) 以上では [開発者ドキュメント](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") は以下のように記されています。
  - `AndroidOpenSSL` として知られる Conscrypt は上述の Bouncy Castle を使用することをお勧めします。これは次の新しい実装を有します。`AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, `Signature:NONEWITHECDSA`
  - GCM にはもはや `IvParameterSpec.class` を使用すべきではありません。代わりに `GCMParameterSpec.class` を使用します。
  - ソケットは `OpenSSLSocketImpl` から `ConscryptFileDescriptorSocket` および `ConscryptEngineSocket` に変更されています。
  - ヌルパラメータを持つ `SSLSession` は NullPointerException を返します。
  - 鍵を生成するために入力バイトとして十分な大きさの配列を持つ必要があります。そうでない場合、InvalidKeySpecException がスローされます。
  - ソケット読み込みが中断された場合は、`SocketException` を取得します。
- Android 9 (API level 28) 以上では [Android 開発者ブログ](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P") はより積極的な変更を記しています。
  - `getInstance` メソッドを使用してプロバイダを指定し、P より下の任意の API をターゲットにすると、警告を得ます。P 以上をターゲットにすると、エラーを得ます。
  - `Crypto` プロバイダは現在削除されています。これをコールすると `NoSuchProviderException` が返されます。
- Android 10 (API level 29) では [開発者ドキュメント](https://developer.android.com/about/versions/10/behavior-changes-all#security "Security Changes in Android 10") にすべてのネットワークセキュリティの変更がリストされています。

Android SDK はセキュアな鍵生成および使用を記述するためのメカニズムを提供します。Android 6.0 (API level 23) ではアプリケーションで正しい鍵の使用を保証するために使用できる `KeyGenParameterSpec` クラスを導入しました。

API 23 以降での AES/CBC/PKCS7Padding の使用例を以下に示します。

```Java
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

`KeyGenParameterSpec` は鍵を暗号化および復号化に使用できることを示しますが、署名や検証などの他の目的は示しません。さらに、ブロックモード (CBC)、パディング (PKCS #7) を指定し、ランダム化された暗号化が必要であることを明示します (これがデフォルトです) 。`"AndroidKeyStore"` はこの例で使用される暗号化サービスプロバイダの名前です。これにより鍵は鍵の保護のために受益者である `AndroidKeyStore` に格納されることが自動的に保証されます。

GCM はもうひとつの AES ブロックモードであり、他の古いモードよりもセキュリティ上の利点があります。暗号的によりセキュアであることに加えて、認証も提供します。CBC (および他のモード) を使用する場合は、認証は HMAC を使用して別に実行する必要があります ( "[Android の改竄とリバースエンジニアリング](0x05c-Reverse-Engineering-and-Tampering.md)" の章を参照してください) 。GCM は [パディングをサポートしない](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore") AES の唯一のモードであることに注意します。

上記の仕様に違反して生成された鍵の使用を試みるとセキュリティ例外が発生します。

その鍵を使用して復号する例を以下に示します。

```Java
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_CBC
        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore AndroidKeyStore = AndroidKeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = AndroidKeyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the IV and the encryptedBytes
```

IV (初期化ベクトル) および暗号化されたバイト列の両方を格納する必要があります。さもなければ解読は不可能です。

暗号文を復号する方法を以下に示します。`input` は暗号化されたバイト配列であり、`iv` は暗号ステップからの初期化ベクトルです。

```Java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

IV は毎回ランダムに生成されるため、後で復号するために暗号文 (`encryptedBytes`) とともに保存する必要があります。

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

この例では 4096 ビットの鍵サイズ (すなわち、モジュラスサイズ) で RSA 鍵のペアを作成します。

注意：NDK を使用して暗号操作とハードコードされた鍵を隠す必要があるとする誤った考えが広まっています。しかし、このメカニズムを使用することは効果的ではありません。攻撃者はツールを使用して、使用されているメカニズムを見つけ出し、メモリ内の鍵のダンプを作成できます。また、radare2 (詳細については「リバースエンジニアリングと改竄」の章の「[ネイティブコードの逆アセンブル](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")」セクションを参照) でコントロールフローを解析できます。Android 7.0 (API level 24) 以降では、プライベート API を使用することは許可されません。代わりにパブリック API をコールする必要があります。[Android 開発者ブログ](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers") に記載されているように、それを隠すことの効果にさらに影響します。

#### 静的解析

コード内の暗号化プリミティブの使用を見つけます。最もよく使用されるクラスとインタフェースのいくつかを以下に示します。

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- `java.security.*` および `javax.crypto.*` パッケージにあるその他のもの

「モバイルアプリの暗号化」の章に記載されているベストプラクティスに従っていることを確認します。使用されている暗号アルゴリズムの構成が [NIST](https://www.keylength.com/en/4/ "NIST recommendations - 2016") および[BSI](https://www.keylength.com/en/8/ "BSI recommendations - 2017") のベストプラクティスと整合し、強力であるとみなされていることを確認します。`SHA1PRNG` は暗号学的にセキュアではないため、もはや使用していないことを確認します。
最後に、鍵がネイティブコードにハードコードされていないこと、および安全でないメカニズムがこのレベルで使用されていないことを確認します。

### 乱数生成のテスト (MSTG-CRYPTO-6)

#### 概要

暗号にはセキュアな擬似乱数生成 (PRNG) が必要です。標準の Java クラスは十分なランダム性を提供しないため、実際に攻撃者が生成される次の値を推測し、この推測を使用して別のユーザーになりすましたり機密情報にアクセスしたりする可能性があります。

一般的に、`SecureRandom` を使用すべきです。しかし、Android 4.4 (API level 19) 以前の Android バージョンをサポートする場合には、[PRNG を適切に初期化できない](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts") Android 4.1-4.3 (API level 16-18) バージョンのバグを回避するために更なる注意が必要です。

ほとんどの開発者は引数なしでデフォルトコンストラクタを介して `SecureRandom` をインスタンス化する必要があります。他のコンストラクタはより高度な用途のためにあり、誤って使用されると、ランダム性やセキュリティが低下する可能性があります。`SecureRandom` を支援する PRNG プロバイダは `/dev/urandom` デバイスファイルをデフォルトのランダム性のソースとして使用します [#nelenkov] 。

#### 静的解析

乱数生成器のインスタンスをすべて特定して、カスタムまたは既知のセキュアでない `java.util.Random` クラスを探します。このクラスは与えられた各シード値に対して同じ一連の番号を生成します。その結果、一連の数は予測可能となります。

以下のサンプルソースコードは脆弱な乱数生成を示しています。

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

代わりに、その分野の専門家により現時点で強力であると考えられている十分に検証されたアルゴリズムを使用し、適切な長さのシードを持つ十分にテストされた実装を選択すべきです。

デフォルトコンストラクタを使用して作成されていない `SecureRandom` のすべてのインスタンスを特定します。シード値を指定するとランダム性が低下する可能性があります。システム指定のシード値を使用して 128 バイト長の乱数を生成する [`SecureRandom` の引数なしコンストラクタ](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") を選択します。

一般的に、PRNG が暗号的にセキュアであると宣言されていない場合 (`java.util.Random` など) 、それはおそらく統計的 PRNG であり、セキュリティ上機密であるコンテキストに使用すべきではありません。
擬似乱数生成器が既知であり、シードが推定できる場合、その生成器は [予測可能な数値を生成します](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded "Proper seeding of SecureRandom") 。128 ビットシードは「十分にランダムな」数値を生成するためのよい出発点です。

以下のサンプルソースコードはセキュアな乱数の生成を示しています。

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

#### 動的解析

攻撃者はどのタイプの脆弱な疑似乱数生成器 (PRNG) が使用されているかを知ることで、[Java Random で行われたように](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java") 、以前に観測された値に基づいて次の乱数値を生成する概念実証を書くことは簡単です。非常に脆弱なカスタム乱数生成器の場合にはパターンを統計的に観測することが可能かもしれません。推奨される方法はとにかく APK を逆コンパイルしてアルゴリズムを検査することです (静的解析を参照してください) 。

ランダム性をテストしたい場合には、数の大きなセットをキャプチャし Burp の [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp\'s Sequencer") で確認してランダム性の品質がどれほど良いかを見ます。

### 鍵管理のテスト (MSTG-STORAGE-1, MSTG-CRYPTO-1 および MSTG-CRYPTO-5)

#### 概要

このセクションでは暗号鍵を格納するさまざまな方法とそれらをテストする方法について説明します。私たちは鍵マテリアルの生成および保存の最もセキュアな方法からセキュアではない方法に至るまで説明します。

鍵マテリアルを扱う最もセキュアな方法は単にデバイスにそれを保存しないことです。これはアプリケーションが暗号操作を実行する必要があるたびに、パスフレーズを入力するようにユーザーに指示する必要があることを意味しています。これはユーザーエクスペリエンスの観点からは理想的な実装ではありませんが、鍵マテリアルを扱う最もセキュアな方法です。その理由は鍵マテリアルが使用されている間、メモリ内の配列でのみ利用可能になるためです。その鍵がもはや必要なくなれば、配列をゼロにすることができます。これにより攻撃ウィンドウを可能な限り最小限にします。鍵マテリアルはファイルシステムに触れず、パスフレーズは保存されません。しかし、一部の暗号はそれらのバイト配列を適切にクリーンアップしないことに注意します。例えば、BouncyCastle の AES 暗号は最新の作業鍵を常にクリーンアップするとは限りません。次に、BigInteger ベースの鍵 (秘密鍵 (private key) など) をヒープから削除することも簡単にゼロにすることもできません。最後に、鍵をゼロにしようとするときには注意します。鍵の内容が実際にゼロになっていることを確認する方法については "[Android のデータストレージ](0x05d-Testing-Data-Storage.md)" のセクションを参照してください。

対称暗号鍵は Password Based Key Derivation Function version 2 (PBKDF2) を使用してパスフレーズから生成できます。この暗号プロトコルはセキュアであり、かつブルートフォースできない鍵を生成するように設計されています。以下のコードはパスワードに基づいて強力な暗号鍵を生成する方法を示しています。

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //Initiliaze objects and variables for later use
    int iterationCount = 10000;
    int saltLength     = keyLength / 8;
    SecureRandom random = new SecureRandom();

    //Generate the salt
    byte[] salt = new byte[saltLength];
    random.nextBytes(salt);

    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
}
```

上記の手法はパスワードと必要な鍵長をビットに含む文字配列、例えば 128 または 256 ビットの AES 鍵が必要です。PBKDF2 アルゴリズムにより使用される 10000 ラウンドの反復回数を定義します。これによりブルートフォース攻撃の作業負荷が大幅に増加します。鍵長に等しいソルトサイズを定義し、ビットからバイトへの変換に気をつけて 8 で割ります。`SecureRandom` クラスを使用して、ランダムにソルトを生成します。同じパスワードが与えられた後に同じ暗号鍵が生成されることを確実にするために、明らかに、このソルトは固定に保ちたいものです。ソルトを `SharedPreferences` に非公開で格納できることに注意します。リスクの高いデータの場合には Android のバックアップメカニズムからソルトを除外することを推奨します。詳細は「[Android のデータストレージ](0x05d-Testing-Data-Storage.md)」を参照してください。
ルート化デバイスやパッチされていないデバイス、パッチ適用 (再パッケージなど) されたアプリケーションをデータの脅威として考慮すると、`AndroidKeystore` の鍵でソルトを暗号化するほうがよいかもしれないことに注意します。その後、パスワードベースの暗号化 (PBE) 鍵は Android 8.0 (API level 26) まで推奨される `PBKDF2WithHmacSHA1` アルゴリズムを使用して生成されます。そこからは `PBKDF2withHmacSHA256` を使用することがベストです。これは鍵サイズが異なります。

今では、定期的にユーザーにパスフレーズを促すことはすべてのアプリケーションにとって機能するものではないことは明らかです。その場合には必ず [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html "Android AndroidKeyStore API") を使用してください。この API は鍵マテリアルにセキュアなストレージを提供するために特別に開発されました。あなたのアプリケーションだけが生成した鍵にアクセスできます。Android 6.0 からは AndroidKeyStore は指紋センサーが存在する場合にハードウェア支援も強制されます。これは鍵マテリアルをセキュアにするために専用の暗号チップまたは Trusted Platform Module (TPM) が使用されていることを意味します。

但し、`AndroidKeyStore` API は Android のさまざまなバージョンで大幅に変更されていることに注意します。以前のバージョンでは `AndroidKeyStore` API は公開鍵と秘密鍵 (private key) のペア (RSA など) の保存のみをサポートしていました。対称鍵のサポートは Android 6.0 (API level 23) 以降でのみ追加されています。結果として、開発者は対称鍵をセキュアに保存するためにさまざまな Android API レベルを処理する必要があります。

Android 5.1 (API level 22) 以下で動作するデバイスで対称鍵をセキュアに保存するには、公開鍵と秘密鍵 (private key) のペアを生成する必要があります。公開鍵を使用して対象鍵を暗号化し、秘密鍵 (private key) を `AndroidKeyStore` に保存します。暗号化された対称鍵は `SharedPreferences` に安全に保存できます。対称鍵が必要なときにはいつでも、アプリケーションは `AndroidKeyStore` から秘密鍵 (private key) を取り出し、対称鍵を復号します。

鍵が `AndroidKeyStore` 内で生成及び使用され `KeyInfo.isinsideSecureHardware` が `true` を返す場合、その鍵をダンプしたり暗号操作を監視したりすることができないことはご存知の通りです。`PBKDF2withHmacSHA256` を使用してまだ到達可能でダンプ可能なメモリに鍵を生成するか、もしくは鍵が決してメモリに入り込まないであろう `AndroidKeyStore` を使用するか、最終的に何がより安全であるかは議論の余地があります。Android 9 (API level 28) では `PBKDF2withHmacSHA256` を使用するよりも有利となるように、TEE と `AndroidKeyStore` を分離するために追加のセキュリティ拡張が実装されています。しかし、近い将来、その議題についてより多くのテストと調査が行われるでしょう。

#### キーストアへのセキュアなキーインポート

Android 9 (API level 28) は鍵を `AndroidKeystore` 内にセキュアにインポートする機能を追加します。最初に `AndroidKeystore` は `PURPOSE_WRAP_KEY` を使用して鍵ペアを生成します。これも認証証明書で保護されるべきです。このペアは `AndroidKeystore` にインポートされる鍵を保護することを目的としています。暗号化された鍵は `SecureKeyWrapper` フォーマットの ASN.1 エンコードメッセージとして生成されます。これにはインポートされた鍵が使用を許される方法の説明も含まれています。その後、鍵はラッピング鍵を生成した特定のデバイスに属する `AndroidKeystore` ハードウェア内で復号化されるため、デバイスのホストメモリに平文で現れることはありません。

<img src="Images/Chapters/0x5e/Android9_secure_key_import_to_keystore.png" alt="Secure key import into Keystore" width="500">

```java
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

上記のコードは SecureKeyWrapper フォーマットで暗号化された鍵を生成するときに設定されるさまざまなパラメータを表しています。詳細については [`WrappedKeyEntry`](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry "WrappedKeyEntry") の Android ドキュメントを確認してください。

KeyDescription AuthorizationList を定義するときに、以下のパラメータが暗号化鍵セキュリティに影響を与えます。

- `algorithm` パラメータは鍵が使用される暗号化アルゴリズムを指定します。
- `keySize` パラメータは鍵のサイズをビット単位で指定します。鍵のアルゴリズムに対して普通に計測されます。
- `digest` パラメータは署名および検証オペレーションを実行するために鍵とともに使用できるダイジェストアルゴリズムを指定します。

#### 鍵構成証明

暗号プリミティブによる多要素認証、クライアント側での機密データのセキュアな保管など、ビジネスに不可欠な操作のために Android Keystore に大きく依存しているアプリケーションに対して、Android は [鍵構成証明 (Key Attestation)](https://developer.android.com/training/articles/security-key-attestation "Key Attestation") の機能を提供します。これは Android Keystore を介して管理される暗号マテリアルのセキュリティを分析するのに役立ちます。Android 8.0 (API level 26) 以降、Google スイーツアプリでデバイス認証を取得する必要があるすべての新しい (Android 7.0 以降) デバイスでは鍵構成証明が必須になりました。このようなデバイスでは [Google ハードウェア構成証明ルート証明書](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root Certificate") で署名された構成証明鍵を使用し、鍵構成証明プロセスの中で検証されます。

鍵構成証明の中で、鍵ペアのエイリアスを指定し、リターンとして証明書チェーンを取得します。これを使用して、鍵ペアのプロパティを検証できます。チェーンのルート証明書が [Google ハードウェア構成証明ルート証明書](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root certificate") であり、ハードウェア内での鍵ペアの保存に関連するチェックが行われた場合、デバイスがハードウェアレベルの鍵構成証明をサポートし、その鍵が Google がセキュアであると信ずるハードウェア支援のキーストアにあることが保証されます。また、構成証明チェーンに他のルート証明書がある場合、Google はそのハードウェアのセキュリティについて一切主張しません。

鍵構成証明プロセスはアプリケーション内で直接実装できますが、セキュリティ上の理由からサーバー側で実装することをお勧めします。以下は鍵構成証明をセキュアに実装するための高レベルのガイドラインです。

- サーバーは CSPRNG (暗号論的にセキュアな乱数生成器) を使用してセキュアに乱数を作成することにより鍵構成証明プロセスを開始しすべきであり、同じものをチャレンジとしてユーザーに送信すべきです。
- クライアントはサーバーから受信したチャレンジを使用して `setAttestationChallenge` API を呼び出し、それから `KeyStore.getCertificateChain` を使用して構成証明証明書チェーンを検索すべきです。
- 構成証明レスポンスを検証のためにサーバーに送信し、鍵構成証明レスポンスの検証のために以下のチェックを実行すべきです。
  - ルートまでの証明書チェーンを検証し、有効性、完全性、信頼性などの証明書のサニティチェックを実行します。
  - ルート証明書が検証プロセスを信頼できるものにする Google 構成証明ルート鍵で署名されているかどうかを確認します。
  - 証明書チェーンの最初の要素内に現れる構成証明証明書拡張データを抽出し、以下のチェックを実行します。
    - 構成証明チャレンジが構成証明プロセスを開始する際にサーバーで生成されたものと同じ値であることを検証します。
    - 鍵構成証明レスポンスの署名を検証します。
    - ここで鍵マスターのセキュリティレベルをチェックし、デバイスにセキュアな鍵ストレージメカニズムがあるかどうかを確認します。鍵マスターはセキュリティのコンテキストで動作し、すべてのセキュアなキーストア操作を提供するソフトウェアの一部です。セキュリティレベルは `Software`, `TrustedEnvironment`, `StrongBox` のいずれかになります。
    - さらに、Software, TrustedEnvironment, StrongBox のいずれかである構成証明セキュリティレベルをチェックし、その構成証明証明書がどのように生成されたかを確認します。また、目的、アクセス時間、認証要件など鍵に関する他のいくつかのチェックを行い、鍵属性を検証します。

Android Keystore 構成証明レスポンスの一般的な例は以下のようになります。

```json
{
    "fmt": "android-key",
    "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bd...",
    "attStmt": {
        "alg": -7,
        "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53...",
        "x5c": [
            "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130...",
            "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b300906035504061...",
            "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b3..."
        ]
    }
}
```

上記の JSON スニペット でのキーの意味は以下の通りです。
        `fmt`: 構成証明ステートメントの書式識別子
        `authData`: 構成証明用の認証データを表します
        `alg`: 署名に使用されるアルゴリズム
        `sig`: 署名
        `x5c`: 構成証明証明書チェーン

注意: `sig` は _authData_ と `clientDataHash` (サーバーから送信されたチャレンジ) を連結し、alg 署名アルゴリズムを使用して資格情報秘密鍵を介して署名することにより生成されます。最初の証明書の公開鍵を使用して、サーバー側でも同じものが検証されます。

実装ガイドラインの詳細については、 [Google サンプルコード](https://github.com/googlesamples/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java "Google Sample Code For Android Key Attestation") を参照できます。

セキュリティ分析の観点から、アナリストは鍵構成証明のセキュアな実装のために以下のチェックを実行したほうがよいでしょう。

- 鍵構成証明が全体的にクライアント側で実装されているかどうかを確認します。このようなシナリオでは、アプリケーションの改竄、メソッドフックなどにより同じものが簡単に回避される可能性があります。
- 鍵構成証明を開始する際にサーバーがランダムチャレンジを使用しているかどうかを確認します。これを怠ると、実装がセキュアではなくなり、その結果としてリプレイ攻撃に対して脆弱になります。またチャレンジの無作為性に関するチェックも実行すべきです。
- サーバーが鍵構成証明レスポンスの完全性を検証しているかどうかを確認します。
- サーバーがチェーン内の証明書に対して完全性検証、信頼性検証、有効性などの基本的なチェックを実行しているかどうかを確認します。

#### アンロックされたデバイスのみでの復号化

セキュリティを高めるために Android 9 (API level 28) では `unlockedDeviceRequied` フラグを導入しています。`setUnlockedDeviceRequired` メソッドに `true` を渡すことで、アプリはデバイスがロックされたときに `AndroidKeystore` に格納されている鍵が復号化されることを防ぎ、復号化を許可する前にスクリーンをアンロックする必要があります。

#### StrongBox ハードウェアセキュリティモジュール

Android 9 (API level 28) 以降を実行しているデバイスは `StrongBox Keymaster` を持つことができます。これは独自の CPU 、セキュリティストレージ、真正乱数生成器、パッケージ改竄に耐するメカニズムを持つハードウェアセキュリティモジュールにある Keymaster HAL の実装です。この機能を使うには `AndroidKeystore` を使用して鍵を生成またはインポートするときに、`KeyGenParameterSpec.Builder` クラスまたは `KeyProtection.Builder` クラスの `setIsStrongBoxBacked` メソッドに `true` を渡す必要があります。StrongBox が実行時に使用されていることを確認するには、`isInsideSecureHardware` が `true` を返し、鍵に関連付けられた特定のアルゴリズムと鍵サイズで StrongBox Keymaster が利用できない場合にシステムがスローする `StrongBoxUnavailableException` をスローしていないことを確認します。

#### 鍵使用の認可

Android デバイスでの鍵の不正使用を軽減するために、Android KeyStore では鍵を生成またはインポートするときにアプリに鍵の認可された使用を指定できます。一度されると、認可は変更できません。

Android により提供されているもう一つの API は `KeyChain` です。これは認証情報ストレージの 秘密鍵 (private key) とそれに対応する証明書チェーンへのアクセスを提供します。これはキーチェーンの対話の必要性と共有の性質からあまり使用されません。詳細については [開発者ドキュメント](https://developer.android.com/reference/android/security/KeyChain "Keychain") を参照してください。

暗号鍵を保存するあまりセキュアではない方法は Android の SharedPreferences におくことです。[SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html "Android SharedPreference API") が [MODE_PRIVATE](https://developer.android.com/reference/android/content/Context.html#MODE_PRIVATE "MODE_PRIVATE") で初期化された場合、そのファイルはそれを作成したアプリケーションによってのみ読み取り可能です。但し、ルート化されたデバイスでは、ルートアクセス権を持つ他のアプリケーションが他のアプリの SharedPreference ファイルを簡単に読み取ることができます。MODE_PRIVATE が使われれているかどうかは関係ありません。AndroidKeyStore についてはそうではありません。AndroidKeyStore のアクセスはカーネルレベルで管理されているため、AndroidKeyStore が鍵をクリアまたは破棄することなくバイパスするにはかなりの作業とスキルが必要です。

最後の三つのオプションはソースコード内にハードコードされた暗号化鍵を使用すること、堅牢な属性に基づく予測可能な鍵導出関数を持つこと、そして `/sdcard/` などのパブリックな場所に生成された鍵を格納することです。明らかに、ハードコードされた鍵は進むべき道ではありません。これはアプリケーションのすべてのインスタンスが同じ暗号化鍵を使用することを意味します。攻撃者は、ネイティブまたは Java/Kotlin のいずれに格納されているかにかかわらず、ソースコードから鍵を抽出するために、一度作業を行うだけで済みます。その結果、攻撃者はアプリケーションにより暗号化された他のデータを復号できます。
次に、他のアプリケーションからアクセス可能な識別子に基づく予測可能な鍵導出関数がある場合、攻撃者は KDF を見つけて、鍵を見つけるためにデバイスにそれを適用するだけで済みます。最後に、暗号化鍵をパブリックに格納することもあまりお勧めできません。他のアプリケーションがパブリックパーティションを読むパーミッションを持ち、鍵を盗むことができるためです。

#### 静的解析

コードで暗号プリミティブの使用を特定します。最も頻繁に使用されるクラスとインタフェースの一部を以下に示します。

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `AndroidKeyStore`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKeySpec`, `KeyInfo`
- `java.security.*` および `javax.crypto.*` パッケージにあるその他のもの

例として、ハードコードされた暗号鍵の使用の特定方法を示します。最初に ```Baksmali``` を使用して Smali バイトコードのコレクションに DEX バイトコードを逆アセンブルします。

```shell
$ baksmali d file.apk -o smali_output/
```

Smali バイトコードファイルのコレクションがあるので、```SecretKeySpec``` クラスの使用法についてファイルを検索できます。今取得した Smali ソースコードを単に再帰的に grep することでこれを行います。Smali のクラス記述子は `L` で始まり `;` で終わることに注意してください。

```shell
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;"
```

これは `SecretKeySpec` クラスを使用するすべてのクラスをハイライト表示します。ハイライトされたすべてのファイルを調べて、鍵マテリアルを渡すのに使用されているバイトはどれかをトレースします。下の図は出荷準備が完了したアプリケーションでこの評価を行った結果を示しています。読みやすくするため、DEX バイトコードから Java コードにリバースエンジニアしました。静的バイト配列 `Encrypt.keyBytes` にハードコードされ初期化された静的暗号鍵の使用がはっきりとわかります。

<img src="Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

ソースコードにアクセスできる場合には、少なくとも以下について確認します。

- 鍵を格納するためにどのメカニズムが使用されているかチェックします。他のすべてのソリューションよりも `AndroidKeyStore` を推奨します。
- TEE の使用を確実にするために多層防御メカニズムが使用されているかどうかをチェックします。例えば、時刻有効性は強制されていますか？ハードウェアセキュリティの使用はコードにより評価されていますか？詳細については [KeyInfo のドキュメント](https://developer.android.com/reference/android/security/keystore/KeyInfo "KeyInfo") を参照してください。
- ホワイトボックス暗号化ソリューションの場合、その有効性を調べるか、その分野の専門家に相談します。
- 鍵の目的の検証には特に注意します。以下はその例です。
  - 非対称鍵の場合、秘密鍵 (private key) は署名にのみ使用され、公開鍵 (public key) は暗号化にのみ使用されることを確認します。
  - 対象鍵が複数の目的に再利用されないことを確認します。別のコンテキストで使用される場合には、新しい対象鍵を生成すべきです。

#### 動的解析

暗号メソッドをフックし、使用されている鍵を解析します。暗号操作が行われている間にファイルシステムへのアクセスを監視して、鍵マテリアルがどこに書き込まれるか、どこから読み取られるかを評価します。

### 参考情報

- [#nelenkov] - N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.

#### 暗号についての参考情報

- Android Developer blog: Crypto provider deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: cryptography changes in android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Android Developer blog: changes for NDK developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- security providers -  <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle  - <https://rtyley.github.io/spongycastle/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- Android Developer documentation - <https://developer.android.com/guide>
- NIST keylength recommendations - <https://www.keylength.com/en/4/>
- BSI recommendations - 2017 - <https://www.keylength.com/en/8/>

#### SecureRandom についての参考情報

- Proper seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>
- Burpproxy its Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>

#### 鍵管理のテストについての参考情報

- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>
- KeyInfo documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>

#### 鍵構成証明についての参考情報

- Android Key Attestation - <https://developer.android.com/training/articles/security-key-attestation>
- W3C Android Key Attestation - <https://www.w3.org/TR/webauthn/#android-key-attestation>
- Verifying Android Key Attestation - <https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d>
- Attestation and Assertion - <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion>
- Google Sample Codes - <https://github.com/googlesamples/android-key-attestation/tree/master/server>
- FIDO Alliance Whitepaper - <https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf>
- FIDO Alliance TechNotes - <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>

##### OWASP MASVS

- MSTG-STORAGE-1: "個人識別情報、ユーザー資格情報、暗号化鍵などの機密データを格納するために、システムの資格情報保存機能が適切に使用されている。"
- MSTG-CRYPTO-1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- MSTG-CRYPTO-2: "アプリは実績のある暗号化プリミティブの実装を使用している。"
- MSTG-CRYPTO-3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- MSTG-CRYPTO-4: "アプリはセキュリティ上の目的で広く非推奨と考えられる暗号プロトコルやアルゴリズムを使用していない。"
- MSTG-CRYPTO-5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"
- MSTG-CRYPTO-6: "すべての乱数値は、十分に安全な乱数生成器を用いて生成している。"
