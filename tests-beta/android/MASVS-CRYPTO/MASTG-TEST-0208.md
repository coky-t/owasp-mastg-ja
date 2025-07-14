---
platform: android
title: 不十分な鍵サイズ (Insufficient Key Sizes)
id: MASTG-TEST-0208
type: [static]
weakness: MASWE-0009
profiles: [L1, L2]
---

## 概要

このテストケースでは、Android アプリでの不十分な鍵サイズの使用を探します。そのためには、Android で利用できる暗号フレームワークとライブラリ、および暗号鍵の生成、検査、管理に使用されるメソッドに注目する必要があります。

Java Cryptography Architecture (JCA) は鍵生成のための基本的なクラスを提供しており、移植性や古いシステムとの互換性が懸念される場合に直接使用されることがよくあります。

- **`KeyGenerator`**: [`KeyGenerator`](https://developer.android.com/reference/javax/crypto/KeyGenerator) クラスは、AES、DES、ChaCha20、Blowfish などの対称鍵やさまざまな HMAC 鍵を生成するために使用されます。鍵サイズは [`init(int keysize)`](https://developer.android.com/reference/javax/crypto/KeyGenerator#init(int)) メソッドを使用して指定できます。
- **`KeyPairGenerator`**: [`KeyPairGenerator`](https://developer.android.com/reference/java/security/KeyPairGenerator) クラスは、非対称暗号 (RSA、EC など) の鍵ペアを生成するために使用されます。鍵サイズは [`initialize(int keysize)`](https://developer.android.com/reference/java/security/KeyPairGenerator#initialize(int)) メソッドを使用して指定できます。

詳細については ["鍵生成"](../../../Document/0x05e-Testing-Cryptography.md#key-generation) に関する MASTG セクションを参照してください。

## 手順

1. [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などの静的解析ツールをコードに対して実行し、鍵を生成する暗号関数の使用を探します。

## 結果

出力には不十分な鍵長が使用されている場所のリストを含む可能性があります。

## 評価

ソースコード内に不十分な鍵サイズの使用を見つけることができた場合、そのテストケースは不合格です。たとえば、量子コンピューティング攻撃を考慮すると、1024 ビットの鍵サイズは RSA 暗号では不十分であるとみなされ、128 ビットの鍵サイズは AES 暗号では不十分であるとみなされます。
