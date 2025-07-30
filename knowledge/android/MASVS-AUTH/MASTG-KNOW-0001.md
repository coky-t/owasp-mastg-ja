---
masvs_category: MASVS-AUTH
platform: android
title: 生体認証 (Biometric Authentication)
---

生体認証は認証に便利なメカニズムですが、使用時にさらなる攻撃対象領域をもらたします。Android 開発者ドキュメントでは [生体認証を用いたロック解除のセキュリティを測定する](https://source.android.com/docs/security/features/biometric/measure "[生体認証を用いたロック解除のセキュリティを測定する") に興味深い [概要](https://source.android.com/docs/security/features/biometric) と指標が記載されています。

Android プラットフォームは生体認証用に三つの異なるクラスを提供しています。

- Android 10 (API レベル 29) および以降: `BiometricManager`
- Android 9 (API レベル 28) および以降: `BiometricPrompt`
- Android 6.0 (API レベル 23) および以降: `FingerprintManager` (Android 9 (API レベル 28) で廃止)

<img src="../../../Document/Images/Chapters/0x05f/biometricprompt-architecture.png" width="100%" />

[`BiometricManager`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricManager "BiometricManager") クラスを使用して、そのデバイスでバイオメトリックハードウェアが利用可能かどうか、およびユーザーにより構成されているかどうかを検証できます。そうである場合、[`BiometricPrompt`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricPrompt "BiometricPrompt") クラスを使用して、システムが提供するバイオメトリックダイアログを表示できます。

`BiometricPrompt` クラスは大幅に改善されています。Android での生体認証の一貫した UI を持ち、指紋以外のセンサーもサポートしています。

Android の Biometric API の非常に詳細な概要と説明は [Android 開発者ブログ](https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html "One Biometric API Over all Android") に公開されています。

[生体認証ダイアログを表示する](https://developer.android.com/identity/sign-in/biometric-auth)

## Biometric ライブラリ

Android は [Biometric](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android")  というライブラリを提供します ([androidx.biometric API リファレンス](https://developer.android.com/reference/kotlin/androidx/biometric/package-summary) も参照してください)。これは `BiometricPrompt` および `BiometricManager` API の互換バージョンを提供します。Android 10 に実装されており、Android 6.0 (API 23) に完全対応する機能を備えています。

Android 開発者ドキュメントにリファレンス実装と [生体認証ダイアログを表示](https://developer.android.com/training/sign-in/biometric-auth "生体認証ダイアログを表示") する方法の説明があります。

`BiometricPrompt` クラスで利用できる二つの `authenticate` メソッドがあります。それらの一つは [`CryptoObject`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject.html "CryptoObject") を待ち受けます。これにより生体認証に追加のセキュリティレイヤーが追加されます。

CryptoObject を使用する際の認証フローは以下の通りです。

- アプリは `setUserAuthenticationRequired` および `setInvalidatedByBiometricEnrollment` に true をセットして KeyStore に鍵を作成します。さらに `setInvalidatedByBiometricEnrollment` に -1 をセットする必要があります。
- この鍵はユーザーを認証している情報 (セッション情報や認証トークンなど) を暗号化するために使用されます。
- データを復号するために KeyStore から鍵をリリースする前に、有効な生体認証セットを提示する必要があります。これは `authenticate` メソッドと `CryptoObject` を通して妥当性確認されます。
- このソリューションはルート化デバイスでもバイパスできません。KeyStore からの鍵は生体認証の成功後にのみ使用できるためです。

authenticate メソッドの一環として `CryptoObject` が使用されない場合、Frida を使用してバイパスできます。詳細については「動的計装」セクションを参照してください。

開発者は Android が提供するいくつかの [validation クラス](https://source.android.com/security/biometric#validation "Validation of Biometric Auth") を使用して、アプリでの生体認証の実装をテストできます。

## 機密性の高いデータや操作を保護するための生体認証

クレデンシャル確認フローは Android 6.0 以降で利用可能であり、ユーザーがロック画面保護でアプリ固有のパスワードを入力する必要がないようにするために使用されます。代わりに、ユーザーがデバイスに直近でログインしている場合は、クレデンシャル確認を使用して `AndroidKeystore` から暗号マテリアルをロック解除できます。つまり、ユーザーが設定された制限時間 (`setUserAuthenticationValidityDurationSeconds`) 内にデバイスをロック解除した場合であり、それ以外の場合はデバイスを再度ロック解除する必要があります。

クレデンシャル確認のセキュリティはロック画面で設定された保護と同程度の強度であることに注意してください。これは単純な予測としてロック画面パターンがよく使用されることを意味します。そのため L2 のセキュリティコントロールを必要とするアプリではクレデンシャル確認の使用はお勧めしません。

ロック画面が設定されていることを確認します。

```java
KeyguardManager mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
if (!mKeyguardManager.isKeyguardSecure()) {
    // Show a message that the user hasn't set up a lock screen.
}
```

- ロック画面で保護される鍵を作成します この鍵を使用するには、ユーザーは直近の X 秒間にデバイスをロック解除する必要があります。そうでなければデバイスを再びロック解除する必要があります。この時間が長すぎないように注意します。デバイスをロック解除したユーザーとアプリを使用しているユーザーが同じであることを確認することが難しくなります。

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

## 鍵の無効化

Android 7.0 (API レベル 24) では `KeyGenParameterSpec.Builder` に `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` メソッドを追加しました。`invalidateKey` の値が `true` (デフォルト) に設定されている場合、新しい指紋が登録されると、指紋認証に有効な鍵は不可逆的に無効化されます。これは、攻撃者が追加の指紋を登録できたとしても、鍵を取得できなくなります。

## 生体認証サードパーティ SDK

指紋認証やその種類の生体認証はもっぱら Android SDK とその API に基づいていることを確認します。そうでない場合、代替 SDK があらゆる脆弱性に対して適切に検証されていることを確認します。その SDK は TEE/SE がバックにあり、生体認証に基づいて (暗号) 機密をロック解除することを確認します。この機密は他のものによりロック解除されるべきではなく、有効な生体エントリによってロック解除されるべきです。そのようにして、指紋ロジックがバイパスできることがあってはいけません。
