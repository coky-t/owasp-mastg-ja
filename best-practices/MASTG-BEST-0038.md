---
title: 生体認証には明示的なユーザー確認を要求する (Require Explicit User Confirmation for Biometric Authentication)
alias: require-explicit-user-confirmation-for-biometric-authentication
id: MASTG-BEST-0038
platform: android
knowledge: [MASTG-KNOW-0001]
---

明示的なユーザー認可が必要な機密性の高い操作 (支払いや健康データへのアクセスなど) には、`BiometricPrompt.Builder` で [`setConfirmationRequired(true)`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.PromptInfo.Builder#setConfirmationRequired(boolean)) を設定するか、確認を必要とするデフォルトの動作に任せます。

`setConfirmationRequired(false)` が使用される場合、顔認識などの受動的な生体情報は、デバイスがユーザーの生体データを検出すると同時に、暗黙的にユーザーを認証できます。これは、ユーザーが操作を積極的に承認することなく認証が完了する可能性があることを意味し、高価値なアクションには適していないことがあります。

[Android ドキュメント](https://developer.android.com/identity/sign-in/biometric-auth#no-explicit-user-action) には、明示的な確認は、特に受動的な生体手法が使用される場合、ユーザーが意図的に機密性の高い操作を開始したことの保証を提供することを注記しています。
