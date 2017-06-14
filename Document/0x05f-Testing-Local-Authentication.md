## ローカル認証のテスト (Android アプリ)

MASVS の認証とセッション管理要件のほとんどは iOS や Android の特定の実装とは独立して検証できるアーキテクチャおよびサーバー側の問題を指しています。したがって MSTG ではこれらのテストケースをプラットフォームに依存しない方法で説明します (付録「認証とセッション管理 (エンドポイント)」を参照ください) 。しかしローカル認証メカニズムが使用される場合もあります。例えば、アプリをローカルで「アンロック」したり、ユーザーが既存のセッションを再開するための簡単な方法を提供します。ここではこれらのケースについて説明します。

### 生体認証のテスト

#### 概要

Android 6.0 では指紋でユーザーを認証するパブリック API が導入されました。指紋ハードウェアへのアクセスは <code>FingerprintManager</code> クラス <sup>[1]</sup> を通じて提供されます。アプリは <code>FingerprintManager</code> オブジェクトをインスタンス化し、<code>authenticate()</code> メソッドをコールすることで指紋認証を要求できます。呼び出し元はコールバックメソッドを登録して、認証プロセスの可能性がある結果 (成功、失敗、エラー) を処理します。

Android KeyGenerator と一緒に指紋 API を使用することで、アプリはユーザーの指紋で「ロックされていない」暗号鍵を作成できます。これはより便利な形でユーザーログインを実装するために使用できます。例えば、ユーザーがリモートサービスにアクセスできるようにするために、対称鍵を作成し、ユーザー PIN や認証トークンを暗号化することができます。鍵を作成する際に <code>setUserAuthenticationRequired(true)</code> をコールすることで、ユーザーが鍵を取得するために指紋を使用して再認証することを保証します。暗号化された認証データ自体は通常のストレージ (SharedPreferences など) を使用して保存できます。

この比較的合理的な方法のほかに、安全でない方法で指紋認証を実装することもできます。例えば、開発者は <code>onAuthenticationSucceeded</code> コールバック <sup>3</sup> がコールされたかどうかや Samsung Pass SDK がインスタンスに使用されている時のみに基づいて認証成功とすることを選択できます。しかし、このイベントはユーザーが生体認証を行ったことを証明するものではありません。このようなチェックは計装を使用して簡単にパッチ適用やバイパスが可能です。キーストアを利用することはユーザーが実際に指紋を入力したことを合理的に確認する唯一の方法です。

もちろん、キーストアが危険にさらされない限りです。これは [5] で報告され、主に [6] で説明されているような場合です。既知の CVE として、例えば CVE-2016-2431, CVE-2016-2432, CVE-2015-6639, CVE-2015-6647 が登録されています。したがって、常にセキュリティパッチレベルをチェックすべきです。

```java
	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", 	Locale.getDefault());
	sdf.parse(Build.VERSION.SECURITY_PATCH).after(sdf.parse("2016-05-01"));
```


#### 静的解析

最初に実際の Android SDK が指紋評価に使用されていることを確認します。Samsung Pass などのベンダー固有の SDK は本質的に欠陥があります。

<code>FingerprintManager.authenticate()</code> のコールを検索します。このメソッドに渡される最初のパラメータは <code>CryptoObject</code> インスタンスが必要です。<code>CryptoObject</code> は FingerprintManager <sup>[2]</sup> によりサポートされている暗号オブジェクトのラッパークラスです。このパラメータに <code>null</code> を設定している場合、指紋認証は純粋にイベントバウンドであるため、セキュリティ上の問題が発生する可能性があります。

CryptoObject でラップされた暗号を初期化するために使用される鍵の生成を追跡します。鍵が <code>KeyGenerator</code> クラスを使用して作成され、<code>KeyGenParameterSpec</code> オブジェクトを作成するときに <code>setUserAuthenticationRequired(true)</code> をコールすることを確認します (以下のコードサンプルも参照ください) 。

認証ロジックを確認します。認証が成功するには、リモートエンドポイントはキーストアから取得した秘密や秘密から派生した値を提示することをクライアントに要求する **必要があります** 。


#### 動的解析

アプリのパッチ適用やランタイム計装の使用によりクライアントの指紋認証をバイパスします。例えば、Frida を使用して <code>onAuthenticationSucceeded</code> コールバックを直接コールします。詳細については「改竄とリバースエンジニアリング (Android)」の章を参照ください。

#### 改善方法

指紋認証は以下の行のように実装する必要があります。

指紋認証が可能であるかどうかを確認します。デバイスは Android 6.0 またはそれ以降 (SDK 23+) で動作し、指紋センサーを搭載している必要があります。チェックすべき二つの前提条件があります。

- The user must have protected their lockscreen 

```java
	 KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
	 keyguardManager.isKeyguardSecure();
```
- Fingerprinthardware must be available:

```java
	 FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();                
```

- At least one finger should be registered:
```java
	fingerprintManager.hasEnrolledFingerprints();
```

- The application should have permission to ask for the users fingerprint:
```java
	context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;
```

If any of those checks failed, the option for fingerprint authentication should not be offered.

指紋認証を設定する際には、<code>KeyGenerator</code> クラスを使用して新しい AES 鍵を作成します。<code>KeyGenParameterSpec.Builder</code> に <code>setUserAuthenticationRequired(true)</code> を追加します。

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
Please note, that since Android 7 you can use the `setInvalidatedByBiometricEnrollment(boolean value)` as a method of the builder. If you set this to true, then the fingerprint will not be invalidated when new fingerprints are enroled. Even though this might provide user-convinience, it opens op a problem area when possible attackers are somehow able to social-engineer their fingerprint in.

暗号化や復号化を実行するには、<code>Cipher</code> オブジェクトを作成し、それを AES 鍵で初期化します。

```java
	SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

    if (mode == Cipher.ENCRYPT_MODE) {
        cipher.init(mode, keyspec);
```

鍵はすぐには使用できないことに注意します。まず <code>FingerprintManager</code> を通じて認証する必要があります。これは <code>FingerprintManager.authenticate()</code> に渡される <code>FingerprintManager.CryptoObject</code> に <code>Cipher</code> をラップすることを含みます。

```java
	cryptoObject = new FingerprintManager.CryptoObject(cipher);
	fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

認証が成功すると、コールバックメソッド <code>onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)</code> がコールされ、認証された CryptoObject を認証結果から取得できます。

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
	cipher = result.getCryptoObject().getCipher();

	(... do something with the authenticated cipher object ...)
}
```

Please bare in mind that the keys might not be always in secure hardware, for that you can do the following to validate the posture of the key:

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);
                KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);
secetkeyInfo.isInsideSecureHardware()
```
Please note that, on some systems, you can make sure that the biometric authentication policy itself is hardware enforced as well. This is checked by:

```java
	keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

完全な例については、Deivi Taka <sup>[4]</sup> のブログ記事を参照ください。


#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.6: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"

##### CWE

- CWE-287 - Improper Authentication
- CWE-604 - Use of Client-Side Authentication

##### その他

- [1] FingerprintManager - https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.html
- [2] FingerprintManager.CryptoObject - https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html
- [3] https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder.html#setUserAuthenticationRequired(boolean)
- [4] Securing Your Android Appps with the Fingerprint API - https://www.sitepoint.com/securing-your-android-apps-with-the-fingerprint-api/#savingcredentials
- [5] Android Security Bulletins - https://source.android.com/security/bulletin/
- [6] Extracting Qualcomm's KeyMaster Keys - Breaking Android Full Disk Encryption - http://bits-please.blogspot.co.uk/2016/06/extracting-qualcomms-keymaster-keys.html

##### ツール

N/A
