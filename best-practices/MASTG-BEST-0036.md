---
title: 生体認証には暗号バインディングを使用する (Use Cryptographic Binding for Biometric Authentication)
alias: use-cryptographic-binding-for-biometric-authentication
id: MASTG-BEST-0036
platform: android
knowledge: [MASTG-KNOW-0001]
---

生体認証で保護された機密性の高い操作には、[`BiometricPrompt.authenticate()`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt#authenticate(androidx.biometric.BiometricPrompt.PromptInfo,androidx.biometric.BiometricPrompt.CryptoObject)) を、`setUserAuthenticationRequired(true)` を用いて設定された [Android Keystore](https://developer.android.com/privacy-and-security/keystore) キーで裏付けられた [`CryptoObject`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.CryptoObject) とともに使用します。これは認証結果をキー操作に暗号的にバインドし、機密性の高い操作は生体認証の検証に成功した後にのみ処理されることを確保します。

`CryptoObject` なしでは、認証はイベント依存であり、`onAuthenticationSucceeded` コールバックのみに依存します。これは実行時ロジック操作に影響を受けやすくなります。たとえば、生体認証の検証を実際に通過せず、コールバックをフックしてに成功を返すことが可能です。

## キーストアキー設定

[`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) でキーを生成する場合、以下を設定します。

- [`setUserAuthenticationRequired(true)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationRequired(boolean)): キーを使用する前にユーザー認証を要求します。
- [`setUserAuthenticationParameters(0, type)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,int)): タイムアウトに `0` を設定すると、個々の暗号操作ごとに認証を要求します。機密性の高い操作では有効期間の拡張を避けます。デバイスが後で不正な人物によりアクセスされた場合でも、キーは有効期間全体にわたって使用可能なままとなります。

> [!NOTE]
> [`setUserAuthenticationValidityDurationSeconds(int)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int)) は API レベル 30 で `setUserAuthenticationParameters(int, int)` に代わり、非推奨となりました。
