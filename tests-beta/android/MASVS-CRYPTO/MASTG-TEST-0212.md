---
title: コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
platform: android
id: MASTG-TEST-0212
type: [static]
weakness: MASWE-0014
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0012]
---

## 概要

このテストケースでは、Android アプリケーションでハードコードされた鍵の使用を探します。そのためには、ハードコードされた鍵の暗号実装に注目する必要があります。Java Cryptography Architecture (JCA) は `SecretKeySpec`](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec) クラスを提供しており、バイト配列から [`SecretKey`](https://developer.android.com/reference/javax/crypto/SecretKey) を作成できます。

## 手順

1. [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) などのツールで [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用するか、[Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) などのツールで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) (動的解析) を使用して、コード内の対称鍵暗号のインスタンスをすべて特定し、ハードコードされた暗号鍵の使用を探します。

## 結果

出力にはハードコードされた鍵が使用されている場所のリストを含む可能性があります。

## 評価

セキュリティ上重要なコンテキストで使用されるハードコードされた鍵を見つけた場合、そのテストケースは不合格です。
