---
platform: android
title: 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
id: MASTG-TEST-0247
apis: [KeyguardManager, BiometricManager#canAuthenticate]
type: [static]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
---

## 概要

このテストでは、パスコードが設定されたデバイス上でアプリが実行されているかどうかを検証します。Android アプリはプラットフォームが提供する API を使用することで、安全な [画面ロック (PIN やパスワードなど)](https://support.google.com/android/answer/9079129) が有効になっているかどうかを判断できます。具体的には、アプリは [KeyguardManager](https://developer.android.com/reference/android/app/KeyguardManager) API を利用できます。この API は [isDeviceSecure()](https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure()) と [isKeyguardSecure()](https://developer.android.com/reference/android/app/KeyguardManager#isKeyguardLocked()) のメソッドを提供し、デバイスに安全なロックメカニズムが設定されているかどうかをチェックできます。

さらに、アプリは [BiometricManager#canAuthenticate(int)](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager#canAuthenticate(int)) API を使用して、生体認証が利用可能で使用できるかどうかをチェックできます。Android の生体認証ではフォールバックとして安全な画面ロックを必要とするため、このメソッドは [KeyguardManager](https://developer.android.com/reference/android/app/KeyguardManager) が利用できないか、デバイス製造業者によって制限されている場合の代替チェックとして機能します。

アプリが認証のために生体認証に依存する場合、[BiometricPrompt](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt) API を使用するか、**Android KeyStore System** を介して暗号鍵へのアクセスに認証を要求することで、生体認証を確実に適用すべきです。ただし、アプリはシステムレベルでユーザーに生体認証を有効にするように **強制することはできず**、機密性の高い機能にアクセスためにアプリ内での使用のみを強制できます。

## 手順

1. [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) を使用して、安全な画面ロックが設定されているかどうかをチェックする API を特定します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが安全な画面ロックの存在を検証するための API を使用していない場合、そのテストは不合格です。
