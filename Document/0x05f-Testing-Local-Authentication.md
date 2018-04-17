## Android のローカル認証

ローカル認証では、アプリはデバイス上でローカルに保存された資格情報に対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、指紋を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、このプロセスはリモートサービスで既存のセッションを再開するためのユーザーの利便性を提供するような理由で、またはある重要な機能を保護するためのステップアップ認証の手段として呼び出されます。

### 生体認証のテスト

#### 概要

Android Marshmallow (6.0) では指紋でユーザーを認証するパブリック API が導入されました。指紋ハードウェアへのアクセスは [FingerprintManager クラス](https://developer.android.com/reference/android/hardware/fingerprint/) を通じて提供されます。アプリは `FingerprintManager` オブジェクトをインスタンス化し、`authenticate()` メソッドをコールすることで指紋認証を要求できます。呼び出し元はコールバックメソッドを登録して、認証プロセスの可能性がある結果 (成功、失敗、エラー) を処理します。このメソッドは指紋認証が実際に実行されたことを強く証明するものではないことに注意します。例えば、認証ステップは攻撃者によりパッチアウトされる可能性がありますし、計装を使用して「成功」コールバックがコールされる可能性があります。

Android `KeyGenerator` クラスと共に指紋 API を使用することで、より良いセキュリティが実現します。このメソッドでは、対称鍵がキーストアに格納され、ユーザーの指紋で「アンロック」されます。例えば、リモートサービスへのユーザーアクセスを有効にするには、ユーザー PIN または認証トークンを暗号化する AES 鍵が作成されます。鍵を作成する際に `setUserAuthenticationRequired(true)` をコールすることで、ユーザーが鍵を取得するには再認証する必要があることを確実にします。暗号化された認証資格情報はデバイス上の通常のストレージに直接保存することができます (例、`SharedPreferences`) 。この設計はユーザーが実際に認可された指紋を実際に入力したことを確実にする比較的安全な方法です。但し、この設定はアプリが暗号操作中にメモリ内に対称鍵を保持する必要があり、実行時にアプリのメモリにアクセスする攻撃者に潜在的に開示されることに注意します。

よりセキュアな選択肢は非対称暗号を使用することです。ここでは、モバイルアプリがキーストアに非対称鍵ペアを作成し、サーバーバックエンド上に公開鍵を登録します。その後のトランザクションは秘密鍵で署名され、公開鍵を使用してサーバーにより検証されます。これの利点はキーストアから秘密鍵を抽出することなく、キーストア API を使用してトランザクションに署名できることです。その結果、メモリダンプや計装を使用することにより攻撃者が鍵を取得することは不可能となります。

#### 静的解析

`FingerprintManager.authenticate()` コールを探すことから始めます。このメソッドに渡される最初のパラメータは FingerprintManager によりサポートされる [Crypto オブジェクトのラッパークラス](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html) である `CryptoObject` インスタンスである必要があります。パラメータが `null` に設定されている場合、これは指紋認証が単にイベントバウンドであることを意味し、セキュリティの問題が発生する可能性があります。

暗号ラッパーを初期化するために使用される鍵の作成は `CryptoObject` にトレースバックされます。`KeyGenParameterSpec` オブジェクトの作成中にコールされる `setUserAuthenticationRequired(true)` を加えた `KeyGenerator` クラスを使用して鍵が作成されたことを確認します (以下のコードサンプルを参照) 。

認証ロジックを必ず検証してください。認証が成功するには、リモートエンドポイントはクライアントがキーストアから取得したシークレット、シークレットから派生した値、またはクライアント秘密鍵で署名された値 (上記参照) を提示する **必要があります** 。

指紋認証を安全に実装するには以下のいくつかの簡単な原則に従い、最初にその認証の種類が利用可能かどうかを確認することを開始します。最も基本的なこととして、デバイスは Android 6.0 もしくはそれ以降 (API 23+) を実行する必要があります。他に四つの前提条件も確認する必要があります。

- 指紋ハードウェアが利用可能である必要があります。

```Java
	 FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();                
```

- ユーザーは保護されたロックスクリーンを持つ必要があります。

```Java
	 KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
	 keyguardManager.isKeyguardSecure();
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

##### 対称鍵を用いた指紋認証

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

```
	SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

    if (mode == Cipher.ENCRYPT_MODE) {
        cipher.init(mode, keyspec);
```

注意、新しい鍵はすぐには使用できません。最初に `FingerprintManager` で認証する必要があります。これは `Cipher` オブジェクトを `FingerprintManager.CryptoObject` にラップし、認識される前に `FingerprintManager.authenticate()` に渡されます。

```java
	cryptoObject = new FingerprintManager.CryptoObject(cipher);
	fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

認証が成功すると、その時点でコールバックメソッド `onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)` がコールされ、認証された `CryptoObject` が結果から取得できます。

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
	cipher = result.getCryptoObject().getCipher();

	(... 認証された cipher オブジェクトで何かをします ...)
}
```

##### 非対称鍵ペアを用いた指紋認証

非対称暗号を使用して指紋認証を実装するには、まず `KeyPairGenerator` クラスを使用して署名鍵を作成し、サーバに公開鍵を登録します。その後、クライアント上で署名しサーバ上で署名を検証することにより、個々のデータを認証できます。指紋 API を使用してリモートサーバに認証する詳細な例は [Android Developers Blog](https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html "Authenticating to remote servers using the Fingerprint API") にあります。

鍵ペアは以下のように生成されます。

```Java
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

```Java
Signature.getInstance("SHA256withECDSA");
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
PrivateKey key = (PrivateKey) keyStore.getKey(MY_KEY, null);
signature.initSign(key);
CryptoObject cryptObject = new FingerprintManager.CryptoObject(signature);

CancellationSignal cancellationSignal = new CancellationSignal();
FingerprintManager fingerprintManager =
        context.getSystemService(FingerprintManager.class);
fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
```

以下のようにして、バイト配列 `inputBytes` の内容に署名できます。

```Java
Signature signature = cryptoObject.getSignature();
signature.update(inputBytes);
byte[] signed = signature.sign();
```

- トランザクションを署名する場合には、ランダムなノンスを生成し、署名されるデータに追加することに注意します。そうしなければ、攻撃者はトランザクションをリプレイできる可能性があります。

- 対称指紋認証を使用して認証を実装するには、チャレンジレスポンスプロトコルを使用します。

##### その他のセキュリティ機能

Android Nougat (API 24) は `KeyGenParameterSpec.Builder` に `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` メソッドを追加します。`invalidateKey` 値が "true" (デフォルト) に設定されている場合、指紋認証に有効な鍵は新しい指紋が登録された際に不可逆的に無効になります。これにより、たとえ攻撃者が追加の指紋を登録できたとしても、鍵を取得できなくなります。

#### 動的解析

アプリにパッチを当てるか実行時計装を使用して、クライアント上の指紋認証をバイパスします。例えば、Frida を使用して `onAuthenticationSucceeded` コールバックメソッドを直接コールできます。詳細については「Android の改竄とリバースエンジニアリング」の章を参照してください。

### 参考情報

#### OWASP Mobile Top 10 2016

- M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M4-Insecure_Authentication.html

#### OWASP MASVS

- V4.7: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"

#### CWE

- CWE-287 - Improper Authentication
- CWE-604 - Use of Client-Side Authentication
