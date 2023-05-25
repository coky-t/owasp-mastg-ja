---
masvs_v1_id:
- MSTG-AUTH-8
masvs_v2_id:
- MASVS-AUTH-2
platform: android
title: 生体認証のテスト (Testing Biometric Authentication)
masvs_v1_levels:
- L2
---

## 概要

## 静的解析

バイオメトリックサポートを提供するベンダーやサードパーティーの SDK はかなりありますが、個別の危険性があることに注意します。サードパーティー SDK を使用して機密性の高い認証ロジックを処理する場合は十分に気を付けてください。

## 動的解析

この詳細な [Android KeyStore と生体認証に関するブログ記事](https://labs.withsecure.com/blog/how-secure-is-your-android-keystore-authentication "How Secure is your Android Keystore Authentication?") をご覧ください。この調査には生体認証のセキュアではない実装をテストし、バイパスできるかどうかを試みることができる二つの Frida スクリプトが含まれています。

- [Fingerprint bypass](https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass.js "Fingerprint Bypass"): この Frida スクリプトは `BiometricPrompt` クラスの `authenticate` メソッドで `CryptoObject` が使用されていない場合に認証をバイパスします。認証の実装は `onAuthenticationSucceded` コールバックがコールされることに依存しています。
- [Fingerprint bypass via exception handling](https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass-via-exception-handling.js "Fingerprint bypass via exception handling"): この Frida スクリプトは `CryptoObject` が使用されているが正しくない方法で使用されている場合に認証のバイパスを試みます。詳細な説明はブログ記事の "Crypto Object Exception Handling" セクションにあります。
