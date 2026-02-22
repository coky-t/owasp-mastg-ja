---
platform: android
title: 有効期間が延長された生体認証で使用される鍵のための API への参照 (References to APIs for Keys used in Biometric Authentication with Extended Validity Duration)
id: MASTG-TEST-0330
apis: [KeyGenParameterSpec.Builder, setUserAuthenticationParameters, setUserAuthenticationValidityDurationSeconds]
type: [static]
weakness: MASWE-0044
profiles: [L2]
knowledge: [MASTG-KNOW-0001, MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012]
best-practices: []
---

## 概要

このテストでは、アプリが暗号鍵の有効期間を延長し、鍵が直後の操作を超えてアンロック状態を維持できるようにしているかどうかをチェックします。[`CryptoObject`](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.CryptoObject) での生体認証を使用する場合、認証の有効期間は認証成功後に鍵が使用可能な期間を決定します。

Android では、開発者は [`setUserAuthenticationParameters(int timeout, int type)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int)) または非推奨の [`setUserAuthenticationValidityDurationSeconds(int)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationValidityDurationSeconds(int)) を使用して、[`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) で鍵を生成する際にこの動作を設定できます。

- **Duration = 0**: 鍵はすべての暗号操作に認証を必要とします。鍵を使用するたびに生体検証を必要となるため、これは最も安全な設定です。
- **Duration > 0**: 鍵は認証成功後に指定期間 (秒単位) アンロック状態のままとなります。期間が分単位または時間単位の長い値に設定されると、スマホに物理アクセスできる攻撃者は生体検証なしで機密操作をトリガーできる可能性があります。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが機密操作に使用される鍵を以下で設定した場合、このテストは不合格です。

- `setUserAuthenticationParameters(duration, type)` (duration > 0 の場合)
- `setUserAuthenticationValidityDurationSeconds(duration)` (duration > 0 の場合)

アプリが `setUserAuthenticationParameters(0, type)` を使用して、機密データリソースや機密機能を保護する際にすべての暗号操作に対して認証を要求する場合、このテストは合格です。

> [!NOTE]
> 認証の有効期間が非ゼロであることは本質的に脆弱性ではありません。複数の関連する操作を迅速に連続して実行する必要がある特定のユースケースでは、数秒程度の短い期間が許容されることがあります。但し、高セキュリティアプリケーションや機密操作では、使用ごとに認証を要求 (duration = 0) することで、不正な鍵の使用やランタイム攻撃に対する最も強力な保護を提供します。
