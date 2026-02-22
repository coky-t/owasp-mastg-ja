---
title: 機密性の高い操作に強力な生体認証を導入する (Enforce Strong Biometrics for Sensitive Operations)
alias: enforce-strong-biometrics-for-sensitive-operations
id: MASTG-BEST-0031
platform: android
knowledge: [MASTG-KNOW-0001]
---

アプリは生体認証で保護される機密性の高い操作に [`BIOMETRIC_STRONG`](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager.Authenticators) オーセンティケータを使用する必要があります。`DEVICE_CREDENTIAL` (PIN、パターン、またはパスワード) を使用すると、ショルダーサーフィンやソーシャルエンジニアリングの影響をより受けやすくなります。

高度なセキュリティが必要な操作 (支払いや健康データへのアクセスなど) では、生体認証を導入することで強力な保護を実現し、ユーザーの存在を検証のみ行います。
