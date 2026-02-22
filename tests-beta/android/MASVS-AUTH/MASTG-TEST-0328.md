---
platform: android
title: 生体認証登録の変更を検出する API への参照 (References to APIs Detecting Biometric Enrollment Changes)
id: MASTG-TEST-0328
apis: [KeyGenParameterSpec.Builder, setInvalidatedByBiometricEnrollment]
type: [static]
weakness: MASWE-0046
profiles: [L2]
knowledge: [MASTG-KNOW-0001]
best-practices: []
---

## 概要

このテストは、生体認証登録の変更 ([生体認証 (Biometric Authentication)](../../../knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md)) 後に、アプリが機密操作を不正アクセスから保護できていないかどうかをチェックします。デバイスのパスコードを入手した攻撃者は、システム設定を介して新しい指紋または顔認識を追加し、アプリでの認証に使用する可能性があります。

この動作は、鍵が生成される際に [`setInvalidatedByBiometricEnrollment`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)) が `false` に設定されている場合に発生します。

デフォルトでは、および `true` に設定している場合、新しい生体認証情報が登録されると鍵は永久に無効化されます。結果として、アイテムが作成された際に生体データが登録されていたユーザーのみがアンロックできます。これは後から登録された生体認証情報による不正アクセスを防止します。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが機密データリソースの保護に使用される鍵に `setInvalidatedByBiometricEnrollment(false)` を使用している場合、このテストは不合格です。

アプリが以下のいずれかである場合、このテストは合格です。

- `setInvalidatedByBiometricEnrollment(true)` を明示的に使用している、または
- デフォルト動作に依存しており、`setUserAuthenticationRequired(true)` が設定されると新しい生体認証登録で鍵を無効化している。
