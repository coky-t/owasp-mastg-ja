---
masvs_category: MASVS-AUTH
platform: android
title: FingerprintManager
deprecated_since: 28
available_since: 23
status: deprecated
deprecation_note: "FingerprintManager クラスは Android 9 (API レベル 28) で非推奨となり、新しいアプリケーションでは使用すべきではありません。代わりに BiometricPrompt API または Android の Biometric ライブラリを使用します。"
covered_by: [MASTG-KNOW-0001]
---

Android 6.0 (API レベル 23) では指紋を介してユーザーを認証する公開 API を導入しましたが、Android 9 (API レベル 28) で非推奨になりました。指紋ハードウェアへのアクセスは [`FingerprintManager`](https://developer.android.com/reference/android/hardware/fingerprint/ "FingerprintManager") クラスを通じて提供されます。アプリは `FingerprintManager` オブジェクトをインスタンス化してその `authenticate` メソッドを呼び出すことで指紋認証を要求できます。呼び出し元はコールバックメソッドを登録して、認証プロセスの可能な結果 (成功、失敗、エラーなど) を処理します。このメソッドは指紋認証が実際に実行されたという強力な証拠を構成しないことに注意してください。例えば、認証ステップが攻撃者によりパッチされたり、"success" コールバックが動的計装を使用してオーバーロードされる可能性があります。

Android `KeyGenerator` クラスと組み合わせて指紋 API を使用することによってより優れたセキュリティを実現できます。このアプローチでは対称鍵が Android KeyStore に保存され、ユーザーの指紋でアンロックされます。例えば、リモートサービスへのユーザーアクセスを有効にするために、認証トークンを暗号化する AES 鍵が作成されます。鍵を作成する際に `setUserAuthenticationRequired(true)` をコールすることにより、ユーザーは鍵を取得するために再認証する必要があることを保証されます。暗号化された認証トークンはデバイスに直接保存できます (例えば Shared Preferences を介して) 。このデザインはユーザーが認証済みの指紋を実際に入力することを保証する比較的安全な方法です。

さらに安全な選択肢は非対称暗号化を使用することです。ここで、モバイルアプリは KeyStore に非対称鍵ペアを作成し、サーバーバックエンドに公開鍵を登録します。そのあと、後のトランザクションは秘密鍵 (private key) で署名され、公開鍵を使用してサーバーにより検証されます。

## 実装

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
