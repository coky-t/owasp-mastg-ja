---
masvs_v1_id:
- MSTG-CRYPTO-2
- MSTG-CRYPTO-3
- MSTG-CRYPTO-4
masvs_v2_id:
- MASVS-CRYPTO-1
platform: android
title: 暗号標準アルゴリズムの設定のテスト (Testing the Configuration of Cryptographic Standard Algorithms)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

コード内の暗号プリミティブのすべてのインスタンスを特定します。すべてのカスタム暗号実装を特定します。以下のものを探すことができます。

- クラス `Cipher`, `Mac`, `MessageDigest`, `Signature`
- インタフェース `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- 関数 `getInstance`, `generateKey`
- 例外 `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*` パッケージを使用するクラス

getInstance へのすべてのコールで、指定しないことによりセキュリティプロバイダのデフォルト `provider` (つまり AndroidOpenSSL 別名 Conscrypt を意味する) を使用することを特定します。 `provider` は `KeyStore` 関連のコードでのみ指定できます (その場合 `KeyStore` は `provider` として提供される必要があります) 。他の `provider` が指定されている場合は、状況とビジネスケース (Android API バージョンなど) にしたがって検証する必要があり、 `provider` は潜在的な脆弱性に対して検査する必要があります。

"[モバイルアプリの暗号化](../../../Document/0x04g-Testing-Cryptography.md)" の章で説明されているベストプラクティスに従っていることを確認します。 [非セキュアおよび非推奨のアルゴリズム](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) および [よくある設定の問題](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues) をご覧ください。

## 動的解析

暗号メソッドで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、使用されている鍵などの入出力値を判別できます。暗号操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込み先または読み取り元を評価します。たとえば、[RMS Runtime Mobile Security](../../../tools/generic/MASTG-TOOL-0037.md) の [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) を使用してファイルシステムを監視します。
