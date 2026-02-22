---
platform: android
title: 明示的なユーザーアクションなしでの認証を強制する API への参照 (References to APIs Enforcing Authentication without Explicit User Action)
id: MASTG-TEST-0329
apis: [BiometricPrompt.PromptInfo.Builder, setConfirmationRequired]
type: [static]
weakness: MASWE-0044
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
best-practices: []
---

## 概要

このテストでは、アプリが生体認証 ([生体認証 (Biometric Authentication)](../../../knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md)) を [明示的なユーザーアクションを必要とせずに](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action) 強制しているかどうかをチェックします。[`android.hardware.biometrics.BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt) API (または API レベル 23 との後方互換性を持つ Jetpack 版の [`androidx.biometric.BiometricPrompt`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt)) を使用する場合、[`BiometricPrompt.Builder`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder) の [`setConfirmationRequired()`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder#setConfirmationRequired(boolean)) メソッドはユーザーが認証を明示的に確認する必要があるかどうかを制御します。これはデフォルトで強制されます。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

明示的なユーザー認証を必要とする機密操作に対してアプリが `setConfirmationRequired()` に `false` を設定している場合、このテストは不合格です。

アプリが以下のいずれかである場合、このテストは合格です。

- 機密操作に対して明示的に `setConfirmationRequired()` に `true` を設定している、または
- デフォルト動作に依存し、確認を必要としている。

> [!NOTE]
> [`setConfirmationRequired(false)`](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action) の使用は本質的に脆弱性ではありません。低リスク操作には適しているかもしれませんが、支払いやデータアクセスなどの機密操作では、アプリは `setConfirmationRequired(true)` を使用するか、デフォルト動作に依存して [ユーザーが認証を明示的に確認することを確保する](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action) 必要があります。
