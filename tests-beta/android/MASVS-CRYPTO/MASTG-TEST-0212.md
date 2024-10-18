---
title: コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
platform: android
id: MASTG-TEST-0212
type: [static]
weakness: MASWE-0014
---

## 概要

このテストケースでは、Android アプリケーションでハードコードされた鍵の使用を探します。そのためには、ハードコードされた鍵の暗号実装に注目する必要があります。Java Cryptography Architecture (JCA) は `SecretKeySpec`](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec) クラスを提供しており、バイト配列から [`SecretKey`](https://developer.android.com/reference/javax/crypto/SecretKey) を作成できます。

## 手順

1. [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などの静的解析ツールをコードに対して実行し、ハードコードされた暗号鍵の使用を探します。

## 結果

出力にはハードコードされた鍵が使用されている場所のリストを含む可能性があります。

## 評価

ハードコードされた鍵を見つけた場合、そのテストケースは不合格です。
