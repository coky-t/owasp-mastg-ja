---
title: 暗号 API での明示的なセキュリティプロバイダへの参照 (References to Explicit Security Provider in Cryptographic APIs)
platform: android
id: MASTG-TEST-0312
type: [static]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0020]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0011]
---

## 概要

Java Cryptography Architecture (JCA) に基づく Android 暗号 API では開発者が `getInstance` メソッドを呼び出す際に [セキュリティプロバイダ](https://developer.android.com/reference/java/security/Provider.html) を指定できます。但し、最新のバージョンではいくつかのプロバイダが非推奨または削除されているため、プロバイダを明示的に指定するとセキュリティ上の問題を引き起こし、互換性を損なう可能性があります。以下に例を示します。

- Android 9 (API レベル 28) 以上をターゲットとするアプリは [プロバイダを指定すると失敗します](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html)。
- _Crypto_ プロバイダは Android 7.0 (API レベル 24) で非推奨となり、[Android 9 (API レベル 28) で削除されました](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms)。
- _BouncyCastle_ プロバイダは [Android 9 (API レベル 28) で非推奨となり、Android 12 (API level 31) で削除されました](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)。

このテストは、JCA API を使用する際に、アプリがデフォルトのプロバイダである `AndroidOpenSSL` ([Conscrypt](https://github.com/google/conscrypt)) 以外のセキュリティプロバイダを明示的に指定するケースを識別します。これは積極的に保守されており、通常は使用する必要があります。`getInstance` 呼び出しを検査し、`KeyStore.getInstance("AndroidKeyStore")` などの正当な例外を除き、名前付きプロバイダの使用をフラグ付けします。

## 手順

1. アプリバイナリに対して [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行して、セキュリティプロバイダを明示的に指定する `getInstance` の呼び出しを探します。

## 結果

出力には `getInstance` 呼び出しでセキュリティプロバイダが明示的に指定されている場所のリストを含む可能性があります。

## 評価

`getInstance` 呼び出しが `KeyStore` 操作に対して `AndroidKeyStore` 以外のセキュリティプロバイダを明示的に指定している場合、そのテストケースは不合格です。各発生箇所をレビューし、プロバイダが実際に必要とされているかどうか、また、その使用が最新の Android バージョンでセキュリティまたは互換性の問題をもたらす可能性があるかどうかを判断します。
