---
title: 機密性の高い操作に強力な生体認証を導入する (Enforce Strong Biometrics for Sensitive Operations)
alias: enforce-strong-biometrics-for-sensitive-operations
id: MASTG-BEST-0031
platform: android
knowledge: [MASTG-KNOW-0001]
---

Android の生体認証で保護された機密性の高い操作では、`BiometricPrompt` を構成して、より弱い生体認証クラスではなく [`BIOMETRIC_STRONG`](https://developer.android.com/reference/androidx/biometric/BiometricManager.Authenticators) を必須とします。Android では `BIOMETRIC_STRONG` をクラス 3 生体認証を使用する認証として定義し、`BIOMETRIC_WEAK` はクラス 2 生体認証に対応します。

操作が生体認証のみとするように想定される場合、許可される認証要素に `DEVICE_CREDENTIAL` を含めてはいけません。`DEVICE_CREDENTIAL` は、生体要素を要求する代わりに、デバイスの画面ロッククレデンシャル (PIN、パターン、パスワード) へのフォールバックを有効にします。本質的に脆弱性ではありませんが、高セキュリティアプリケーション (金融、行政、医療など) ではその使用は意図したセキュリティ態勢を低減し、認証をショルダーサーフィンやソーシャルエンジニアリングへの影響を受けやすくします。
