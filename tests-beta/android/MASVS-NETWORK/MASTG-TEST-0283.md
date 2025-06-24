---
title: サーバーホスト名検証の正しくない実装 (Incorrect Implementation of Server Hostname Verification)
platform: android
id: MASTG-TEST-0283
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## 概要

このテストは、Android アプリが [`verify(...)`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)) を [安全でない方法で](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) 使用して [`HostnameVerifier`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier) を実装し、影響を受ける接続のホスト名検証を事実上オフにしているかどうかを評価します。

このような安全でない実装は、攻撃者が有効な (または自己署名された) 証明書で [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) を実行し、アプリのトラフィックを傍受または改竄することを可能にします。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. ソースコードを検査し、静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行し、`HostnameVerifier` のすべての使用箇所を探します。

## 結果

出力には `HostnameVerifier` が使用されている場所のリストを含みます。

## 評価

サーバーのホスト名が証明書と一致することをアプリが適切に検証 **しない** 場合、そのテストは不合格です。

これには以下のようなケースを含みます。

- **ホスト名を常に受け入れること:** `verify(...)` をオーバーライドして、実際のホスト名や証明書に関係なく、無条件に `true` を返します。
- **過度に広範なマッチングルール:** 意図しないドメインにマッチする寛容なワイルドカードロジックを使用します。
- **不完全な検証カバレッジ:** `SSLSocket` で作成されたチャネルや再ネゴシエーション時に作成されたチャネルなど、すべての SSL/TLS チャネルでホスト名検証を呼び出していません。
- **手動検証の欠如:** 低レベル `SSLSocket` API を使用する場合など、ホスト名検証が自動的に行われない場合には、ホスト名検証を実行しません。

自動化ツールを使用してテストする場合、リバースエンジニアされたコードで報告されたすべての場所を検査して、正しくない実装を確認する必要があります ([逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md))。
