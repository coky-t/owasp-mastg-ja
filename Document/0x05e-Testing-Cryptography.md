# Android の暗号化 API

"[モバイルアプリの暗号化](0x04g-Testing-Cryptography.md)" の章では、一般的な暗号のベストプラクティスを紹介し、モバイルアプリで暗号が間違って使用される場合に起こりうる典型的な欠陥について説明しました。この章では、Android の暗号化 API について詳しく説明します。ソースコード内でのこれらの API の使用をどのように識別し、構成をどのように解釈するかを示します。コードをレビューする際には、このガイドからリンクされている最新のベストプラクティスで使用されている暗号パラメータを必ず比較してください。

Android 内の暗号化システムの主要コンポーネントを特定できます。

- [セキュリティプロバイダ](0x05e-Testing-Cryptography.md#security-provider)
- KeyStore - "データストレージのテスト" の章の [KeyStore](0x05d-Testing-Data-Storage.md#keystore) セクションを参照
- KeyChain - "データストレージのテスト" の章の [KeyChain](0x05d-Testing-Data-Storage.md#keychain) セクションを参照

Android 暗号化 API は Java Cryptography Architecture (JCA) をベースとしています。JCA はインタフェースと実装を分離し、暗号化アルゴリズムのセットを実装できる複数の [セキュリティプロバイダ](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") を含めることを可能にしています。 JCA インタフェースのほとんどは `java.security.*` および `javax.crypto.*` パッケージで定義されています。さらに、 Android 固有のパッケージ `android.security.*` および `android.security.keystore.*` があります。

KeyStore および KeyChain は鍵を保存および使用するための API を提供しています (裏では、 KeyChain API は KeyStore システムを使用しています) 。これらのシステムは暗号鍵のライフサイクル全体を管理することを可能にします。暗号鍵管理を実装するための要件およびガイダンスは [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet") に記載されています。以下のフェーズが考えられます。

- 鍵の生成
- 鍵の使用
- 鍵の保管
- 鍵のアーカイブ
- 鍵の削除

> 鍵の保管については "[データストレージのテスト](0x05d-Testing-Data-Storage.md)" の章で解析していますのでご注意ください。

これらのフェーズは KeyStore/KeyChain システムにより管理されます。ただしシステムの動作はアプリケーション開発者の実装方法により異なります。解析プロセスではアプリケーション開発者が使用する機能に焦点を当てる必要があります。以下の機能を特定および検証する必要があります。

- [鍵生成](0x05e-Testing-Cryptography.md#key-generation)
- [乱数値生成](0x05e-Testing-Cryptography.md#random-number-generation)
- 鍵ローテーション

Apps that target modern API levels, went through the following changes:

- Android 7.0 (API level 24) 以上について [Android 開発者ブログでは以下のように記しています](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Andorid N") 。
  - セキュリティプロバイダの指定を停止することを推奨します。代わりに、常に [パッチされたセキュリティプロバイダ](0x05e-Testing-Cryptography.md#updating-provider) を使用します。
  - `Crypto` プロバイダのサポートは中止されており、このプロバイダは非推奨です。同じことがセキュアランダムのための `SHA1PRNG` にも当てはまります。
- Android 8.1 (API レベル 27) 以上について [開発者ドキュメント](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") は以下のように記しています。
  - `AndroidOpenSSL` として知られる Conscrypt は上述の Bouncy Castle を使用することをお勧めします。これは次の新しい実装を有します。 `AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, `Signature:NONEWITHECDSA`
  - GCM にはもはや `IvParameterSpec.class` を使用すべきではありません。代わりに `GCMParameterSpec.class` を使用します。
  - ソケットは `OpenSSLSocketImpl` から `ConscryptFileDescriptorSocket` および `ConscryptEngineSocket` に変更されています。
  - ヌルパラメータを持つ `SSLSession` は NullPointerException を返します。
  - 鍵を生成するために入力バイトとして十分な大きさの配列を持つ必要があります。そうでない場合 InvalidKeySpecException がスローされます。
  - ソケット読み込みが中断された場合は `SocketException` を取得します。
- Android 9 (API レベル 28) 以上について [Android 開発者ブログ](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P") はさらに多くの変更を記しています。
  - `getInstance` メソッドを使用してセキュリティプロバイダを指定し、 28 未満の API をターゲットにすると、警告が発生します。 Android 9 (API レベル 28) 以上をターゲットにした場合、エラーが発生します。
  - `Crypto` プロバイダは現在削除されています。これをコールすると `NoSuchProviderException` が返されます。
- Android 10 (API レベル 29) について [開発者ドキュメント](https://developer.android.com/about/versions/10/behavior-changes-all#security "Security Changes in Android 10") にすべてのネットワークセキュリティの変更がリストされています。

## 改善方法

アプリ審査の際には以下の推奨事項リストを考慮する必要があります。

- "[モバイルアプリの暗号化](0x04g-Testing-Cryptography.md)" の章で説明されているベストプラクティスが守られていることを確認します。
- セキュリティプロバイダが最新アップデートであることを確認します - [セキュリティプロバイダの更新](https://developer.android.com/training/articles/security-gms-provider "Updating security provider") 。
- セキュリティプロバイダの指定を停止し、デフォルト実装 (AndroidOpenSSL, Conscrypt) を使用します。
- Crypto セキュリティプロバイダとその `SHA1PRNG` は非推奨であるため使用を停止します。
- Android KeyStore システムに対してのみセキュリティプロバイダを指定します。
- IV なしでのパスワードベースの暗号化方式の使用を停止します。
- KeyPairGeneratorSpec の代わりに KeyGenParameterSpec を使用します。

### セキュリティプロバイダ

Android は Java Security サービスの実装を `provider` に依存しています。これはセキュアなネットワーク通信と、暗号に依存するその他のセキュアな機能を確保するために重要です。

Android に含まれるセキュリティプロバイダのリストは Android のバージョンや OEM 固有のビルドにより異なります。古いバージョンのセキュリティプロバイダの実装の中には安全性が低いものや脆弱性があるものが知られています。したがって、 Android アプリケーションは正しいアルゴリズムを選択して適切な構成を提供するだけでなく、場合によってはレガシーセキュリティプロバイダの実装の強度にも注意を払う必要があります。

以下のコードを使用して既存のセキュリティプロバイダのセットを一覧表示できます。

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

以下では、セキュリティプロバイダにパッチを適用した後の、 Google Play API を備えたエミュレータで実行中の Android 4.4 (API レベル 19) の出力を示しています。

```default
provider: GmsCore_OpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: AndroidOpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: DRLCertFactory1.0 (ASN.1, DER, PkiPath, PKCS7)
provider: BC1.49 (BouncyCastle Security Provider v1.49)
provider: Crypto1.0 (HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature))
provider: HarmonyJSSE1.0 (Harmony JSSE Provider)
provider: AndroidKeyStore1.0 (Android AndroidKeyStore security provider)
```

以下では Google Play API を備えたエミュレータで実行中の Android 9 (API レベル 28) の出力を示しています。

```default
provider: AndroidNSSP 1.0(Android Network Security Policy Provider)
provider: AndroidOpenSSL 1.0(Android's OpenSSL-backed security provider)
provider: CertPathProvider 1.0(Provider of CertPathBuilder and CertPathVerifier)
provider: AndroidKeyStoreBCWorkaround 1.0(Android KeyStore security provider to work around Bouncy Castle)
provider: BC 1.57(BouncyCastle Security Provider v1.57)
provider: HarmonyJSSE 1.0(Harmony JSSE Provider)
provider: AndroidKeyStore 1.0(Android KeyStore security provider)
```

#### セキュリティプロバイダの更新

コンポーネントに最新のパッチを適用し続けることはセキュリティ原則の一つです。同じことが `provider` にも当てはまります。アプリケーションは使用されているセキュリティプロバイダが最新かどうかを確認し、最新でない場合には [更新してください](https://developer.android.com/training/articles/security-gms-provider "Updating security provider") 。これは [サードパーティーライブラリの脆弱性の確認 (MSTG-CODE-5)](0x05i-Testing-Code-Quality-and-Build-Settings.md#checking-for-weaknesses-in-third-party-libraries) と関連しています。

#### 旧バージョンの Android

古いバージョンの Android (例: Android 7.0 (API レベル 24) より以前のバージョンのみ使用) をサポートする一部のアプリケーションでは、最新のライブラリをバンドルすることが唯一の選択肢かもしれません。Spongy Castle (Bouncy Castle の再パッケージ版) はこのような状況では一般的な選択肢です。Bouncy Castle は Android SDK に含まれているため、再パッケージ化が必要です。[Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") の最新バージョンでは Android に含まれている旧バージョンの [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") で発生した問題が修正されている可能性があります。Android に同梱されている Bouncy Castle ライブラリは [多くの Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java") の対応ほど完全ではないことが多いことに注意します。最後に、 Spongy Castle のような大きなライブラリを同梱と、多くの場合にマルチ dex 化 Android アプリケーションにつながることを心に留めておきます。

### 鍵生成

Android SDK はセキュアな鍵生成および使用を指定するためのメカニズムを提供します。 Android 6.0 (API レベル 23) ではアプリケーションで正しい鍵の使用を保証するために使用できる `KeyGenParameterSpec` クラスを導入しました。

API 23 以降での AES/CBC/PKCS7Padding の使用例を以下に示します。

```java
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

`KeyGenParameterSpec` は鍵を暗号化および復号化に使用できることを示しますが、署名や検証などの他の目的には使用できません。さらに、ブロックモード (CBC) 、パディング (PKCS #7) を指定し、ランダム化された暗号化が必要である (これがデフォルトです) ことを明示的に指定します。 `"AndroidKeyStore"` はこの例で使用されているセキュリティプロバイダの名前です。これにより鍵の保護に役立つ `AndroidKeyStore` に鍵が自動的に保存されることが保証されます。

GCM はもうひとつの AES ブロックモードであり、他の古いモードよりもセキュリティ上の利点があります。暗号的によりセキュアであることに加えて、認証も提供します。 CBC (および他のモード) を使用する場合は、認証は HMAC を使用して別に実行する必要があります ( "[Android の改竄とリバースエンジニアリング](0x05c-Reverse-Engineering-and-Tampering.md)" の章を参照してください) 。 GCM は [パディングをサポートしていない](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore") AES の唯一のモードであることに注意します。

上記の仕様に違反して生成された鍵の使用を試みるとセキュリティ例外が発生します。

その鍵を使用して暗号化する例を以下に示します。

```java
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

IV (初期化ベクトル) および暗号化されたバイト列の両方を保存する必要があります。そうしないと復号はできません。

暗号文を復号する方法を以下に示します。 `input` は暗号化されたバイト配列であり、 `iv` は暗号ステップからの初期化ベクトルです。

```java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

IV は毎回ランダムに生成されるため、後で復号するために暗号文 (`encryptedBytes`) とともに保存する必要があります。

Android 6.0 (API レベル 23) より前では AES 鍵の生成はサポートされていませんでした。結果として、多くの実装では RSA を使用することを選択し、 `KeyPairGeneratorSpec` を使用して非対称暗号化用の公開鍵と秘密鍵のペアを生成するか、あるいは `SecureRandom` を使用して AES 鍵を生成していました。

RSA 鍵ペアの作成に使用される `KeyPairGenerator` および `KeyPairGeneratorSpec` の例を以下の示します。

```java
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

この例では 4096 ビットの鍵サイズ (すなわち、モジュラスサイズ) で RSA 鍵ペアを作成します。

対称暗号鍵は Password Based Key Derivation Function version 2 (PBKDF2) を使用してパスフレーズから生成できます。この暗号プロトコルは暗号鍵を生成するように設計されており、暗号化の目的で使用できます。アルゴリズムの入力パラメータは [脆弱な鍵生成関数](0x04g-Testing-Cryptography.md#weak-key-generation-functions) セクションに従って調整します。以下のコードはパスワードに基づいて強力な暗号鍵を生成する方法を示しています。

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

上記の手法ではパスワードと必要なビット長の鍵 (例えば 128 または 256 ビットの AES 鍵) を含む文字配列が必要です。 PBKDF2 アルゴリズムにより使用される 10,000 ラウンドの反復回数を定義します。反復回数を増やすことでパスワードに対するブルートフォース攻撃の作業負荷が大幅に増加しますが、鍵導出にはより多くの計算能力が必要になるためパフォーマンスに影響を与える可能性があります。鍵長に等しいソルトサイズを定義し、ビットからバイトへの変換を処理するために 8 で除算します。 `SecureRandom` クラスを使用してランダムにソルトを生成します。同じパスワードが与えられた際には何度でも同じ暗号鍵が生成されることを確実にするために、明らかに、このソルトは一定に保ちたいものです。ソルトを `SharedPreferences` に非公開で格納できることに注意します。リスクの高いデータの場合には同期を防ぐために Android のバックアップメカニズムからソルトを除外することを推奨します。

> ルート化デバイスやパッチ適用 (再パッケージなど) されたアプリケーションをデータの脅威として考慮すると、 `AndroidKeystore` に配置された鍵でソルトを暗号化するほうがよいかもしれないことに注意します。 Password-Based Encryption (PBE) 鍵は Android 8.0 (API レベル 26) まで、推奨される `PBKDF2WithHmacSHA1` アルゴリズムを使用して生成されます。より高い API レベルでは `PBKDF2withHmacSHA256` を使用することがベストです。これはハッシュ値が長くなります。

注: NDK を使用して暗号化操作とハードコードされた鍵を隠す必要があるという誤解が広まっています。しかし、このメカニズムを使用しても効果的ではありません。攻撃者は依然としてツールを使用して、使用されているメカニズムを見つけ、メモリ内の鍵のダンプを作成します。次に、制御フローは例えば radare2 と、 Fridaの助けを借りて抽出された鍵、またはその両方を組み合わせた r2frida (詳細は "Android の改竄とリバースエンジニアリング" の章のセクション "[ネイティブコードの逆アセンブル](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")", "[メモリダンプ](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")", "[メモリ内検索](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" を参照) で解析することができます。 Android 7.0 (API レベル 24) 以降では、プライベート API の使用が許可されておらず、代わりにパブリック API を呼び出す必要があります。これは [Android 開発者ブログ](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers") で説明されているように隠蔽の有効性にさらに影響を与えます。

### 乱数生成

暗号にはセキュアな擬似乱数生成 (PRNG) が必要です。 `java.util.Random` のような標準の Java クラスは十分なランダム性を提供しないため、実際に攻撃者が生成される次の値を推測し、この推測を使用して別のユーザーになりすましたり機密情報にアクセスしたりするおそれがあります。

一般的に、 `SecureRandom` を使用すべきです。しかし、Android 4.4 (API レベル 19) 以前の Android バージョンをサポートする場合には、 [PRNG を適切に初期化できない](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts") Android 4.1-4.3 (API レベル 16-18) バージョンのバグを回避するために更なる注意が必要です。

ほとんどの開発者は引数なしでデフォルトコンストラクタを介して `SecureRandom` をインスタンス化する必要があります。他のコンストラクタはより高度な用途のためにあり、誤って使用されると、ランダム性やセキュリティが低下するおそれがあります。 `SecureRandom` を支援する PRNG プロバイダは `AndroidOpenSSL` (Conscrypt) プロバイダから `SHA1PRNG` を使用します。

## 対称暗号のテスト (MSTG-CRYPTO-1)

### 概要

このテストケースは唯一の暗号化手法としてハードコードされた対称暗号に焦点を当てています。以下のチェックを行う必要があります。

- 対称暗号のすべてのインスタンスを特定します
- 特定されたすべてのインスタンスの対称鍵がハードコードされていないかどうかを検証します
- ハードコードされた対称暗号が唯一の暗号化手法として使用されていないかどうかを検証します

### 静的解析

対称鍵暗号のすべてのインスタンスを特定し、対称鍵をロードまたは提供するメカニズムを探します。以下を探します。

- 対称アルゴリズム (`DES`, `AES`, など)
- 鍵生成器の仕様 (`KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, など)
- `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*` パッケージを使用するクラス

特定されたすべてのインスタンスの対称鍵がハードコードされていないかどうかを検証します。対称鍵が以下でないかどうかをチェックします。

- アプリケーションリソースの一部である
- 既知の値から導出できる値である
- コードにハードコードされている

ハードコードされた対称暗号の特定されたすべてのインスタンスが、暗号化の唯一の手法としてセキュリティ上重要なコンテキストで使用されていないことを検証します。

例としてハードコードされた暗号鍵の仕様を特定する方法を示します。最初に ```Baksmali``` を使用して DEX バイトコードを Smali バイトコードファイルのコレクションに逆アセンブルします。

```bash
$ baksmali d file.apk -o smali_output/
```

Smali バイトコードファイルのコレクションができたので、 ```SecretKeySpec``` クラスの使用状況についてファイルを検索してみます。これは取得したばかりの Smali ソースコードを再帰的に grep することで実現します。 Smali のクラス記述子は `L` で始まり `;` で終わることに注意してください。

```bash
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;"
```

これにより `SecretKeySpec` クラスを使用するすべてのクラスが強調表示されます。ここで強調表示されたすべてのファイルを調べ、鍵マテリアルを渡すために使用されるバイト列を追跡します。以下の図は出荷可能アプリケーションでこの評価を実行した結果を示しています。読みやすくするために DEX バイトコードを Java コードにリバースエンジニアリングしました。静的バイト配列 `Encrypt.keyBytes` にハードコードおよび初期化された静的暗号鍵が使用されていることがわかります。

<img src="Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

### 動的解析

暗号化メソッドをフックして、使用されている鍵を解析します。暗号化操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込むまたは読み取る場所を評価します。

## 暗号標準アルゴリズムのテスト (MSTG-CRYPTO-2, MSTG-CRYPTO-3 および MSTG-CRYPTO-4)

### 概要

これらのテストケースでは暗号プリミティブの実装と使用に焦点を当てています。以下のチェックを実行する必要があります。

- 暗号プリミティブのすべてのインスタンスとそれらの実装 (ライブラリまたはカスタム実装) を特定します
- 暗号プリミティブがどのように使用されているかおよびどのように構成されているかを検証します
- 使用されている暗号プロトコルおよびアルゴリズムがセキュリティ上の目的で非推奨ではないかを検証します

### 静的解析

コード内の暗号プリミティブのすべてのインスタンスを特定します。すべてのカスタム暗号実装を特定します。以下を探します。

- クラス `Cipher`, `Mac`, `MessageDigest`, `Signature`
- インタフェース `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- 関数 `getInstance`, `generateKey`
- 例外 `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*` パッケージを使用するクラス

getInstance へのすべてのコールで、指定しないことによりセキュリティプロバイダのデフォルト `provider` (つまり AndroidOpenSSL 別名 Conscrypt を意味する) を使用することを特定します。 `provider` は `KeyStore` 関連のコードでのみ指定できます (その場合 `KeyStore` は `provider` として提供される必要があります) 。他の `provider` が指定されている場合は、状況とビジネスケース (Android API バージョンなど) にしたがって検証する必要があり、 `provider` は潜在的な脆弱性に対して検査する必要があります。

"[モバイルアプリの暗号化](0x04g-Testing-Cryptography.md)" の章で説明されているベストプラクティスに従っていることを確認します。[非セキュアおよび非推奨のアルゴリズム](0x04g-Testing-Cryptography.md#identifying-insecure-and/or-deprecated-cryptographic-algorithms) および [よくある設定の問題](0x04g-Testing-Cryptography.md#common-configuration-issues) をご覧ください。

### 動的解析

暗号化メソッドをフックして、使用されている鍵を解析します。暗号化操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込むまたは読み取る場所を評価します。

## 鍵の目的のテスト (MSTG-CRYPTO-5)

### 概要

このテストケースは目的の検証と同じ暗号鍵の再利用に焦点を当てています。以下のチェックを実行する必要があります。

- 暗号化が使用されているすべてのインスタンスを特定します
- 暗号化が使用される目的 (使用時、転送時、保存時のデータを保護するため) を特定します
- 暗号化のタイプを特定します
- 目的に応じて暗号化が使用されているかどうかを検証します

### 静的解析

暗号化が使用されているすべてのインスタンスを特定します。以下を探します。

- クラス `Cipher`, `Mac`, `MessageDigest`, `Signature`
- インタフェース `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- 関数 `getInstance`, `generateKey`
- 例外 `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` パッケージを使用するクラス

特定されたすべてのインスタンスについて、暗号化の使用目的とそのタイプを特定します。以下を使用します。

- 暗号化/復号化 - データの機密性を確保するため
- 署名/検証 - データの完全性を (場合によっては責任追跡性も) 確保するため
- 保守 - 操作中 (KeyStore へのインポートなど) に鍵を保護するため

さらに、特定された暗号化のインスタンスを使用するビジネスロジックを特定する必要があります。これによりビジネスの観点から暗号化が使用される理由を説明します (保存時に機密性を保護するため、ファイルが Y に属するデバイス X から署名されたことを確認するため、など) 。

検証中には以下のチェックを実行する必要があります。

- 作成時に定義された目的に従って鍵が使用されていることを確認します (KeyProperties を定義できる KeyStore 鍵に関連します)
- 非対称鍵の場合、秘密鍵 (private key) は署名にのみ使用され、公開鍵 (public key) は暗号化のみに使用されることを確認します。
- 対称鍵は複数の目的のために再利用されないことを確認します。別のコンテキストで使用する場合には新しい対称鍵を生成する必要があります。
- 暗号化がビジネスの目的に従って使用されていることを確認します。

### 動的解析

暗号化メソッドをフックして、使用されている鍵を解析します。暗号化操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込むまたは読み取る場所を評価します。

## 乱数生成のテスト (MSTG-CRYPTO-6)

### 概要

このテストケースはアプリケーションで使用される乱数値に焦点を当てています。以下のチェックを実行する必要があります。

- 乱数値が使用されているすべてのインスタンスを特定しており、乱数生成器のすべてのインスタンスは `Securerandom` のものである
- 乱数生成器が暗号的にセキュアであるとみなされないかどうかを検証する
- 乱数生成器がどのように使用されたかを検証する
- アプリケーションにより生成された乱数値のランダム性を検証する

### 静的解析

乱数生成器のインスタンスをすべて特定して、カスタムまたは既知のセキュアでない `java.util.Random` クラスを探します。このクラスは与えられた各シード値に対して同じ一連の番号を生成します。その結果、一連の数は予測可能となります。

以下のサンプルソースコードは脆弱な乱数生成を示しています。

```java
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

```java
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

### 動的解析

攻撃者はどのタイプの脆弱な疑似乱数生成器 (PRNG) が使用されているかを知ることで、[Java Random で行われたように](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java") 、以前に観測された値に基づいて次の乱数値を生成する概念実証を書くことは簡単です。非常に脆弱なカスタム乱数生成器の場合にはパターンを統計的に観測することが可能かもしれません。推奨される方法はとにかく APK を逆コンパイルしてアルゴリズムを検査することです (静的解析を参照してください) 。

ランダム性をテストしたい場合には、数の大きなセットをキャプチャし Burp の [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp\'s Sequencer") で確認してランダム性の品質がどれほど良いかを見ます。

## 参考情報

- [#nelenkov] - N. Elenkov, Android Security Internals, No Starch Press, 2014, Chapter 5.

### 暗号についての参考情報

- Android Developer blog: Changes for NDK Developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- Android Developer blog: Crypto Provider Deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: Cryptography Changes in Android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Android Developer blog: Some SecureRandom Thoughts - <https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html>
- Android Developer documentation - <https://developer.android.com/guide>
- BSI Recommendations - 2017 - <https://www.keylength.com/en/8/>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- NIST Key Length Recommendations - <https://www.keylength.com/en/4/>
- Security Providers -  <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle  - <https://rtyley.github.io/spongycastle/>

### SecureRandom についての参考情報

- Burpproxy its Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>
- Proper Seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>

### 鍵管理のテストについての参考情報

- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- KeyInfo Documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>

### 鍵構成証明についての参考情報

- Android Key Attestation - <https://developer.android.com/training/articles/security-key-attestation>
- Attestation and Assertion - <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion>
- FIDO Alliance TechNotes - <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
- FIDO Alliance Whitepaper - <https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf>
- Google Sample Codes - <https://github.com/googlesamples/android-key-attestation/tree/master/server>
- Verifying Android Key Attestation - <https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d>
- W3C Android Key Attestation - <https://www.w3.org/TR/webauthn/#android-key-attestation>

#### OWASP MASVS

- MSTG-STORAGE-1: "個人識別情報、ユーザー資格情報、暗号化鍵などの機密データを格納するために、システムの資格情報保存機能が適切に使用されている。"
- MSTG-CRYPTO-1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- MSTG-CRYPTO-2: "アプリは実績のある暗号化プリミティブの実装を使用している。"
- MSTG-CRYPTO-3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- MSTG-CRYPTO-4: "アプリはセキュリティ上の目的で広く非推奨と考えられる暗号プロトコルやアルゴリズムを使用していない。"
- MSTG-CRYPTO-5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"
- MSTG-CRYPTO-6: "すべての乱数値は十分に安全な乱数生成器を用いて生成している。"
