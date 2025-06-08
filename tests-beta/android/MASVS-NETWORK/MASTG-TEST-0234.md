---
title: ホスト名を適切に検証しない SSLSocket (SSLSockets not Properly Verifying Hostnames)
platform: android
id: MASTG-TEST-0234
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## 概要

`SSLSocket` は、アプリが明示的に [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)) を使用しない限り、デフォルトではホスト名の検証を行いません。詳細については ["Android ドキュメント"](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket) および ["安全でない HostnameVerifier"](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) を参照してください。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、`SSLSocket` と `HostnameVerifier` のすべての使用箇所を探します。

## 結果

出力には `SSLSocket` と `HostnameVerifier` が使用されている場所のリストを含みます。

## 評価

ホスト名検証が欠落しているか、正しく実装されていない場合、そのテストケースは不合格です。
