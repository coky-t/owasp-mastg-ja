---
masvs_v1_id:
- MSTG-CRYPTO-5
masvs_v2_id:
- MASVS-CRYPTO-2
platform: android
title: 鍵の目的のテスト (Testing the Purposes of Keys)
masvs_v1_levels:
- L1
- L2
profiles: [L2]
status: deprecated
covered_by: ['MASTG-TEST-0307', 'MASTG-TEST-0308']
deprecation_reason: New version available in MASTG V2
---

## 概要

## 静的解析

暗号が使用されているすべてのインスタンスを特定します。以下のものを探すことができます。

- クラス `Cipher`, `Mac`, `MessageDigest`, `Signature`
- インタフェース `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- 関数 `getInstance`, `generateKey`
- 例外 `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*` をインポートしているクラス

特定した各インスタンスについて、その目的とタイプを特定します。以下を使用できます。

- 暗号化/復号化 - データの機密性を確保するため
- 署名/検証 - データの完全性を (場合によっては責任追跡性も) 確保するため
- 保守 - 特定の機密性の高い操作 (KeyStore へのインポートなど) を行う際に鍵を保護するため

さらに、特定した暗号のインスタンスを使用するビジネスロジックを特定する必要があります。

検証の際には以下のチェックを実行する必要があります。

- すべての鍵が作成時に定義した目的に従って使用されていますか？ (これは KeyProperties を定義できる KeyStore 鍵に関連します)
- 非対称鍵の場合、秘密鍵 (private key) は署名にのみ使用され、公開鍵 (public key) は暗号化のみに使用されていますか？
- 対称鍵は複数の目的のために使用されていませんか？別のコンテキストで使用する場合には新しい対称鍵を生成する必要があります。
- 暗号がビジネスの目的に応じて使用されていますか？

## 動的解析

暗号メソッドで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、使用されている鍵などの入出力値を判別できます。暗号操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込み先または読み取り元を評価します。たとえば、[RMS Runtime Mobile Security](../../../tools/generic/MASTG-TOOL-0037.md) の [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) を使用してファイルシステムを監視します。
