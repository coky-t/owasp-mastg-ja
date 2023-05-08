---
masvs_category: MASVS-CRYPTO
platform: android
---

# Android の暗号化 API

## 概要

["モバイルアプリの暗号化"](0x04g-Testing-Cryptography.md) の章では、一般的な暗号のベストプラクティスを紹介し、暗号が間違って使用される場合に起こりうる典型的な問題について説明しました。この章では、Android の暗号化 API について詳しく説明します。ソースコード内でのこれらの API の使用を特定する方法とその暗号設定を判断する方法を示します。コードをレビューする際には、使用されている暗号パラメータをこのガイドからリンクされている現行のベストプラクティスと比較するようにしてください。

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

- Android 7.0 (API level 24) 以上について [Android 開発者ブログでは以下のように記しています](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Android N") 。
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

### 一般的な改善方法

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

コンポーネントに最新のパッチを適用し続けることはセキュリティ原則の一つです。同じことが `provider` にも当てはまります。アプリケーションは使用されているセキュリティプロバイダが最新かどうかを確認し、最新でない場合には [更新してください](https://developer.android.com/training/articles/security-gms-provider "Updating security provider") 。

#### 旧バージョンの Android

古いバージョンの Android (例: Android 7.0 (API レベル 24) より以前のバージョンのみ使用) をサポートする一部のアプリケーションでは、最新のライブラリをバンドルすることが唯一の選択肢かもしれません。Conscrypt ライブラリはさまざまな API レベルで暗号化の一貫性を保ち、より重いライブラリである [Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java") をインポートする必要がないようにするため、この状況では適切な選択といえます。

[Conscrypt for Android](https://github.com/google/conscrypt#android "Conscrypt - A Java Security Provider") は以下の方法でインポートできます。

```groovy
dependencies {
  implementation 'org.conscrypt:conscrypt-android:last_version'
}
```

次に、以下を呼び出してプロバイダを登録する必要があります。

```kotlin
Security.addProvider(Conscrypt.newProvider())
```

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

この例では 4096 ビットの鍵サイズ (すなわち、モジュラスサイズ) で RSA 鍵ペアを作成します。楕円曲線 (Elliptic Curve, EC) 鍵も同様の方法で生成できます。ただし、Android 11 (API レベル 30) 以降、[AndroidKeyStore は EC 鍵での暗号化や復号化をサポートしていません](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher) 。これらは署名にのみ使用できます。

対称暗号鍵は Password Based Key Derivation Function version 2 (PBKDF2) を使用してパスフレーズから生成できます。この暗号プロトコルは暗号鍵を生成するように設計されており、暗号化の目的で使用できます。アルゴリズムの入力パラメータは [脆弱な鍵生成関数](0x04g-Testing-Cryptography.md#weak-key-generation-functions) セクションに従って調整します。以下のコードはパスワードに基づいて強力な暗号鍵を生成する方法を示しています。

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //Initialize objects and variables for later use
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

注: NDK を使用して暗号化操作とハードコードされた鍵を隠す必要があるという誤解が広まっています。しかし、このメカニズムを使用しても効果的ではありません。攻撃者は依然としてツールを使用して、使用されているメカニズムを見つけ、メモリ内の鍵のダンプを作成します。次に、制御フローは例えば radare2 と、 Fridaの助けを借りて抽出された鍵、またはその両方を組み合わせた [r2frida](0x08a-Testing-Tools.md#r2frida) (詳細は "Android の改竄とリバースエンジニアリング" の章のセクション "[ネイティブコードの逆アセンブル](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")", "[メモリダンプ](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")", "[メモリ内検索](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" を参照) で解析することができます。 Android 7.0 (API レベル 24) 以降では、プライベート API の使用が許可されておらず、代わりにパブリック API を呼び出す必要があります。これは [Android 開発者ブログ](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers") で説明されているように隠蔽の有効性にさらに影響を与えます。

### 乱数生成

暗号にはセキュアな擬似乱数生成 (PRNG) が必要です。 `java.util.Random` のような標準の Java クラスは十分なランダム性を提供しないため、実際に攻撃者が生成される次の値を推測し、この推測を使用して別のユーザーになりすましたり機密情報にアクセスしたりするおそれがあります。

一般的に、 `SecureRandom` を使用すべきです。しかし、Android 4.4 (API レベル 19) 以前の Android バージョンをサポートする場合には、 [PRNG を適切に初期化できない](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts") Android 4.1-4.3 (API レベル 16-18) バージョンのバグを回避するために更なる注意が必要です。

ほとんどの開発者は引数なしでデフォルトコンストラクタを介して `SecureRandom` をインスタンス化する必要があります。他のコンストラクタはより高度な用途のためにあり、誤って使用されると、ランダム性やセキュリティが低下するおそれがあります。 `SecureRandom` を支援する PRNG プロバイダは `AndroidOpenSSL` (Conscrypt) プロバイダから `SHA1PRNG` を使用します。
