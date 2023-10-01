---
masvs_category: MASVS-AUTH
platform: android
---

# Android のローカル認証

## 概要

ローカル認証では、アプリはデバイス上でローカルに保存された資格情報に対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、または顔や指紋などの生体特性を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、これはユーザーがより便利にリモートサービスでの既存のセッションを再開するため、またはある重要な機能を保護するためのステップアップ認証の手段として行われます。

["モバイルアプリの認証アーキテクチャ"](0x04e-Testing-Authentication-and-Session-Management.md) の章で前述しているように、テスト技術者はローカル認証が常にリモートエンドポイントで実行されることや暗号プリミティブに基づいている必要があることに注意します。認証プロセスからデータが返らない場合、攻撃者は簡単にローカル認証をバイパスできます。

Android では、ローカル認証のために Android Runtime でサポートされている二つのメカニズムがあります。資格情報の確認フローと生体認証フローです。

### 資格情報の確認フロー

資格情報の確認フローは Android 6.0 以降で利用できます。ユーザーがロック画面の保護機能とともにアプリ固有のパスワードを入力する必要がないようにするために使用されます。代わりに、ユーザーがデバイスに直近でログインしている場合には、資格情報の確認は `AndroidKeystore` から暗号マテリアルをアンロックするために使用できます。つまり、ユーザーが設定された制限時間 (`setUserAuthenticationValidityDurationSeconds`) 内にデバイスをアンロックしたか、もしくは再度デバイスをアンロックする必要があります。

資格情報の確認のセキュリティはロック画面で設定されている保護と同程度の強度しかないことに注意します。これは単純な予測としてロック画面パターンがよく使用されることを意味しています。したがって、L2 のセキュリティコントロールを要求するアプリに資格情報の確認を使用することは推奨しません。

### 生体認証フロー

生体認証は認証に便利なメカニズムですが、使用時にさらなる攻撃領域をもらたします。Android 開発者ドキュメントでは [生体認証アンロックセキュリティの測定](https://source.android.com/security/biometric/measure#strong-weak-unlocks "Measuring Biometric Unlock Security") に興味深い概要と指標が記載されています。

Android プラットフォームは生体認証用に三つの異なるクラスを提供しています。

- Android 10 (API レベル 29) および以降: `BiometricManager`
- Android 9 (API レベル 28) および以降: `BiometricPrompt`
- Android 6.0 (API レベル 23) および以降: `FingerprintManager` (Android 9 (API レベル 28) で廃止)

<img src="Images/Chapters/0x05f/biometricprompt-architecture.png" width="100%" />

[`BiometricManager`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricManager "BiometricManager") クラスを使用して、そのデバイスでバイオメトリックハードウェアが利用可能かどうか、およびユーザーにより構成されているかどうかを検証できます。そうである場合、[`BiometricPrompt`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricPrompt "BiometricPrompt") クラスを使用して、システムが提供するバイオメトリックダイアログを表示できます。

`BiometricPrompt` クラスは大幅に改善されています。Android での生体認証の一貫した UI を持ち、指紋以外のセンサーもサポートしています。

これが指紋センサーのみをサポートし UI を提供しない `FingerprintManager` クラスとの違いです。開発者は独自の指紋 UI を作成する必要があります。

Android の Biometric API の非常に詳細な概要と説明は [Android 開発者ブログ](https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html "One Biometric API Over all Android") に公開されています。

### FingerprintManager (Android 9 (API レベル 28) で廃止)

Android 6.0 (API レベル 23) では指紋を介してユーザーを認証する公開 API を導入しましたが、Android 9 (API レベル 28) で廃止されました。指紋ハードウェアへのアクセスは [`FingerprintManager`](https://developer.android.com/reference/android/hardware/fingerprint/ "FingerprintManager") クラスを通じて提供されます。アプリは `FingerprintManager` オブジェクトをインスタンス化してその `authenticate` メソッドを呼び出すことで指紋認証を要求できます。呼び出し元はコールバックメソッドを登録して、認証プロセスの可能な結果 (成功、失敗、エラーなど) を処理します。このメソッドは指紋認証が実際字実行されたという強力な証拠を構成しないことに注意します。例えば、認証ステップが攻撃者によりパッチされたり、「成功」コールバックが動的計装を使用してオーバーロードされる可能性があります。

Android `KeyGenerator` クラスと組み合わせて指紋 API を使用することによってより優れたセキュリティを実現できます。このアプローチでは対称鍵が Android KeyStore に保存され、ユーザーの指紋でアンロックされます。例えば、リモートサービスへのユーザーアクセスを有効にするために、認証トークンを暗号化する AES 鍵が作成されます。鍵を作成する際に `setUserAuthenticationRequired(true)` をコールすることにより、ユーザーは鍵を取得するために再認証する必要があることを保証されます。暗号化された認証トークンはデバイスに直接保存できます (例えば Shared Preferences を介して) 。このデザインはユーザーが認証済みの指紋を実際に入力することを保証する比較的安全な方法です。

さらにセキュアな選択肢は非対称暗号化を使用することです。ここで、モバイルアプリは KeyStore に非対称鍵ペアを作成し、サーバーバックエンドに公開鍵を登録します。そのあと、後のトランザクションは秘密鍵 (private key) で署名され、公開鍵を使用してサーバーにより検証されます。

### Biometric ライブラリ

Android は [Biometric](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android")  というライブラリを提供します。これは `BiometricPrompt` および `BiometricManager` API の互換バージョンを提供します。Android 10 に実装されており、Android 6.0 (API 23) に完全対応する機能を備えています。

Android 開発者ドキュメントにリファレンス実装と [生体認証ダイアログを表示](https://developer.android.com/training/sign-in/biometric-auth "Show a biometric authentication dialog") する方法の説明があります。

`BiometricPrompt` クラスで利用できる二つの `authenticate` メソッドがあります。それらの一つは [`CryptoObject`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject.html "CryptoObject") を待ち受けます。これにより生体認証に追加のセキュリティレイヤーが追加されます。

CryptoObject を使用する際の認証フローは以下の通りです。

- アプリは `setUserAuthenticationRequired` および `setInvalidatedByBiometricEnrollment` に true をセットして KeyStore に鍵を作成します。さらに `setInvalidatedByBiometricEnrollment` に -1 をセットする必要があります。
- この鍵はユーザーを認証している情報 (セッション情報や認証トークンなど) を暗号化するために使用されます。
- データを復号するために KeyStore から鍵をリリースする前に、有効な生体認証セットを提示する必要があります。これは `authenticate` メソッドと `CryptoObject` を通して妥当性確認されます。
- このソリューションはルート化デバイスでもバイパスできません。KeyStore からの鍵は生体認証の成功後にのみ使用できるためです。

authenticate メソッドの一環として `CryptoObject` が使用されない場合、Frida を使用してバイパスできます。詳細については「動的計装」セクションを参照してください。

開発者は Android が提供するいくつかの [validation クラス](https://source.android.com/security/biometric#validation "Validation of Biometric Auth") を使用して、アプリでの生体認証の実装をテストできます。

### FingerprintManager

> このセクションでは `FingerprintManager` クラスを使用して生体認証を実装する方法について説明します。このクラスは非推奨であり、ベストプラクティスとして [Biometric ライブラリ](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android") を代わりにしようすべきであることに気を付けてください。このセクションはそのような実装に遭遇し解析する必要がある場合に参照するためのものです。

`FingerprintManager.authenticate` コールを探すことから始めます。このメソッドに渡される最初のパラメータは FingerprintManager によりサポートされる [Crypto オブジェクトのラッパークラス](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html "FingerprintManager.CryptoObject") である `CryptoObject` インスタンスである必要があります。パラメータが `null` に設定されている場合、これは指紋認証が単にイベントバウンドであることを意味し、セキュリティの問題が発生する可能性があります。

暗号ラッパーを初期化するために使用される鍵の作成は `CryptoObject` にトレースバックされます。`KeyGenParameterSpec` オブジェクトの作成中にコールされる `setUserAuthenticationRequired(true)` を加えた `KeyGenerator` クラスを使用して鍵が作成されたことを確認します (以下のコードサンプルを参照) 。

認証ロジックを必ず検証してください。認証が成功するには、リモートエンドポイントはクライアントがキーストアから取得したシークレット、シークレットから派生した値、またはクライアント秘密鍵で署名された値 (上記参照) を提示する **必要があります** 。

指紋認証を安全に実装するには以下のいくつかの簡単な原則に従い、最初にその認証の種類が利用可能かどうかを確認することを開始します。最も基本的なこととして、デバイスは Android 6.0 もしくはそれ以降 (API 23+) を実行する必要があります。他に四つの前提条件も確認する必要があります。

- パーミッションは Android Manifest でリクエストされる必要があります。

    ```xml
    <uses-permission
        android:name="android.permission.USE_FINGERPRINT" />
    ```

- 指紋ハードウェアが利用可能である必要があります。

    ```java
    FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();
    ```

- ユーザーは保護されたロックスクリーンを持つ必要があります。

    ```java
    KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    keyguardManager.isKeyguardSecure();  //note if this is not the case: ask the user to setup a protected lock screen
    ```

- 少なくとも一本の指が登録されている必要があります。

    ```java
    fingerprintManager.hasEnrolledFingerprints();
    ```

- アプリケーションにはユーザーの指紋を要求するパーミッションを持つ必要があります。

    ```java
    context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;
    ```

上記のいずれかのチェックが失敗した場合、指紋認証の選択肢を提供してはいけません。

すべての Android デバイスがハードウェア支援のキーストレージを提供するわけではないことを覚えておくことが重要です。`KeyInfo` クラスを使用して、鍵が Trusted Execution Environment (TEE) や Secure Element (SE) などのセキュアなハードウェア内に存在するかどうかを調べることができます。

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);
KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);
secetkeyInfo.isInsideSecureHardware()
```

特定のシステムでは、ハードウェアを使用した生体認証のポリシーを実施することも可能です。これは以下のようにチェックされます。

```java
keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

次に対称鍵ペアを使用して指紋認証を行う方法について説明します。

指紋認証は `KeyGenerator` クラスを使用して新しい AES 鍵を作成することにより実装できます。`KeyGenParameterSpec.Builder` に `setUserAuthenticationRequired(true)` を追加します。

```java
generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

generator.init(new KeyGenParameterSpec.Builder (KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .build()
);

generator.generateKey();
```

保護された鍵で暗号化または復号化を実行するには、`Cipher` オブジェクトを作成しキーエイリアスで初期化します。

```java
SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

if (mode == Cipher.ENCRYPT_MODE) {
    cipher.init(mode, keyspec);
```

注意、新しい鍵はすぐには使用できません。最初に `FingerprintManager` で認証する必要があります。これは `Cipher` オブジェクトを `FingerprintManager.CryptoObject` にラップし、認識される前に `FingerprintManager.authenticate` に渡されます。

```java
cryptoObject = new FingerprintManager.CryptoObject(cipher);
fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

認証が成功すると、コールバックメソッド `onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)` がコールされます。認証された `CryptoObject` が結果から取得できます。

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
    cipher = result.getCryptoObject().getCipher();

    //(... do something with the authenticated cipher object ...)
}
```

次に非対称鍵ペアを使用して指紋認証を行う方法を説明します。

非対称暗号を使用して指紋認証を実装するには、まず `KeyPairGenerator` クラスを使用して署名鍵を作成し、サーバに公開鍵を登録します。その後、クライアント上で署名しサーバ上で署名を検証することにより、個々のデータを認証できます。指紋 API を使用してリモートサーバに認証する詳細な例は [Android Developers Blog](https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html "Authenticating to remote servers using the Fingerprint API") にあります。

鍵ペアは以下のように生成されます。

```java
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
keyPairGenerator.initialize(
        new KeyGenParameterSpec.Builder(MY_KEY,
                KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(true)
                .build());
keyPairGenerator.generateKeyPair();
```

署名のために鍵を使用するには、CryptoObject をインスタンス化し `FingerprintManager` を通して認証する必要があります。

```java
Signature.getInstance("SHA256withECDSA");
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
PrivateKey key = (PrivateKey) keyStore.getKey(MY_KEY, null);
signature.initSign(key);
CryptoObject cryptoObject = new FingerprintManager.CryptoObject(signature);

CancellationSignal cancellationSignal = new CancellationSignal();
FingerprintManager fingerprintManager =
        context.getSystemService(FingerprintManager.class);
fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
```

以下のようにして、バイト配列 `inputBytes` の内容に署名できます。

```java
Signature signature = cryptoObject.getSignature();
signature.update(inputBytes);
byte[] signed = signature.sign();
```

- トランザクションを署名する場合には、ランダムなノンスを生成し、署名されるデータに追加することに注意します。そうしなければ、攻撃者はトランザクションをリプレイできる可能性があります。
- 対称指紋認証を使用して認証を実装するには、チャレンジレスポンスプロトコルを使用します。

### その他のセキュリティ機能

Android 7.0 (API level 24) は `KeyGenParameterSpec.Builder` に `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` メソッドを追加します。`invalidateKey` 値が `true` (デフォルト) に設定されている場合、指紋認証に有効な鍵は新しい指紋が登録された際に不可逆的に無効になります。これにより、たとえ攻撃者が追加の指紋を登録できたとしても、鍵を取得できなくなります。

Android 8.0 (API level 26) は二つのエラーコードを追加します。

- `FINGERPRINT_ERROR_LOCKOUT_PERMANENT`: ユーザーは過度の回数、指紋リーダーを使用してデバイスをアンロックしようと試みた。
- `FINGERPRINT_ERROR_VENDOR`: ベンダー固有の指紋リーダーエラーが発生した。

### 生体認証の実装

ロック画面が設定されていることを確認します。

```java
KeyguardManager mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
if (!mKeyguardManager.isKeyguardSecure()) {
    // Show a message that the user hasn't set up a lock screen.
}
```

- ロック画面で保護される鍵を作成します この鍵を使用するには、ユーザーは直近の X 秒間にデバイスをアンロックする必要があります。そうでなければデバイスを再びアンロックする必要があります。この時間が長すぎないように注意します。デバイスをアンロックしたユーザーとアプリを使用しているユーザーが同じであることを確認することが難しくなります。

    ```java
    try {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder
        keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                        // Require that the user has unlocked in the last 30 seconds
                .setUserAuthenticationValidityDurationSeconds(30)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build());
        keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException
            | InvalidAlgorithmParameterException | KeyStoreException
            | CertificateException | IOException e) {
        throw new RuntimeException("Failed to create a symmetric key", e);
    }
    ```

- ロック画面をセットアップして確認します。

    ```java
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1; //used as a number to verify whether this is where the activity results from
    Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
        startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
    }
    ```

- ロック画面の後に鍵を使用します。

    ```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                //use the key for the actual authentication flow
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
            }
        }
    }
    ```

### サードパーティ SDK

指紋認証やその種類の生体認証はもっぱら Android SDK とその API に基づいていることを確認します。そうでない場合、代替 SDK があらゆる脆弱性に対して適切に検証されていることを確認します。その SDK は TEE/SE がバックにあり、生体認証に基づいて (暗号) 機密をアンロックすることを確認します。この機密は他のものによりアンロックされるべきではなく、有効な生体エントリによってアンロックされるべきです。そのようにして、指紋ロジックがバイパスできることがあってはいけません。
