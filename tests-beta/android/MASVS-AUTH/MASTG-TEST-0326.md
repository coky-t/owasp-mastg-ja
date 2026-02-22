---
platform: android
title: 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0326
apis: [BiometricPrompt, BiometricManager.Authenticators, setAllowedAuthenticators]
type: [static]
weakness: MASWE-0045
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
best-practices: [MASTG-BEST-0031]
---

## 概要

このテストでは、機密性の高い操作のためにデバイスのクレデンシャル (PIN、パターン、パスワード) へのフォールバックを許可する生体認証メカニズム ([生体認証 (Biometric Authentication)](../../../knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md)) をアプリが使用しているかどうかをチェックします。

Android では、[`android.hardware.biometrics.BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt) API (または API レベル 23 との後方互換性を持つ Jetpack 版の [`androidx.biometric.BiometricPrompt`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt)) は [`setAllowedAuthenticators`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setAllowedAuthenticators(int)) メソッドを介してさまざまな種類の [`BiometricManager.Authenticators`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager.Authenticators#constants_1) を受け入れるように構成できます。

オーセンティケータ定数 `DEVICE_CREDENTIAL` が (単独で、または `OR` 演算子 "`|`" を使用して生体オーセンティケータと組み合わせて) 含まれている場合、認証はデバイスクレデンシャルへのフォールバックを許可します。これはパスコードが ([ショルダーサーフィン](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) などを通じて) 侵害の影響を受けやすいため、生体認証のみを要求するよりも弱いとみなされます。

同様に、[`setDeviceCredentialAllowed(true)`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setDeviceCredentialAllowed(boolean)) (API 30 以降は非推奨) を使用しても、デバイスクレデンシャルへのフォールバックを可能になります。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが、保護を必要とする機密データリソースに対して `DEVICE_CREDENTIAL` を含むオーセンティケータ で `BiometricPrompt` を使用している場合、このテストは不合格です。

アプリが、保護を必要とする機密データリソースに対して、生体認証のみのアクセスを強制するために `BIOMETRIC_STRONG` での `BiometricPrompt` のみを使用している場合、このテストは合格です。

> [!NOTE]
> `DEVICE_CREDENTIAL` の使用は本質的に脆弱性ではありませんが、高セキュリティアプリケーション (金融、行政、医療など) では、その使用は弱点や設定ミスとなり、意図したセキュリティ態勢を減らす可能性があります。したがって、この問題は重大な脆弱性ではなく、セキュリティの弱点または堅牢化の問題として分類する方が適切です。
