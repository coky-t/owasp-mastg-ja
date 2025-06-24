---
title: 安全でないカスタムトラスト評価 (Unsafe Custom Trust Evaluation)
platform: android
id: MASTG-TEST-0282
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## 概要

このテストは、Android アプリがカスタム `TrustManager` の一部として [`checkServerTrusted(...)`](https://developer.android.com/reference/javax/net/ssl/X509TrustManager#checkServerTrusted%28java.security.cert.X509Certificate[],%20java.lang.String%29) を [安全でない方法で](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager) 使用し、その `TrustManager` を使用するように構成された接続で証明書バリデーションをスキップするかどうかを評価します。

このような安全でない実装は、攻撃者が有効な (または自己署名された) 証明書で [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) を実行し、アプリのトラフィックを傍受または改竄することを可能にします。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行し、`checkServerTrusted(...)` のすべての使用箇所を探します。

## 結果

出力には `checkServerTrusted(...)` が使用されている場所のリストを含みます。

## 評価

`checkServerTrusted(...)` がカスタム `X509TrustManager` に実装されており、サーバー証明書を正しく検証 **しない** 場合、そのテストは不合格です。

これには以下のようなケースを含みます。

- NSC で十分であるのに、エラーが発生しやすい **`checkServerTrusted(...)` を使用すること**。
- **何もしないトラストマネージャ:** `checkServerTrusted(...)` をオーバーライドして、たとえば証明書チェーンを検証せずにすぐに返したり、常に `true` を返すことで、バリデーションなしですべての証明書を受け入れます。
- **エラーを無視すること:** バリデーションの失敗時に [適切な例外をスロー](https://support.google.com/faqs/answer/6346016) (例: [`CertificateException`](https://developer.android.com/reference/java/security/cert/CertificateException.html) や [`IllegalArgumentException`](https://developer.android.com/reference/java/lang/IllegalArgumentException)) することに失敗するか、それらをキャッチして抑制しています。
- **完全なバリデーションの代わりに [`checkValidity()`](https://developer.android.com/reference/java/security/cert/X509Certificate#checkValidity()) を使用すること:** `checkValidity()` のみに依存すると、証明書が有効期限切れか、まだ有効でないかをチェックしますが、トラストやホスト名の一致は検証 **しません**。
- **明示的にトラストを緩めること:** 開発時やテスト時の利便性のために、トラストチェックを無効にして、自己署名証明書や信頼されていない証明書を受け入れます。
- **[`getAcceptedIssuers()`](https://developer.android.com/reference/javax/net/ssl/X509TrustManager#getAcceptedIssuers()) の誤用**: 適切な処理を行わずに `null` または空の配列を返すと、発行者バリデーションを事実上無効になる可能性があります。

自動化ツールを使用してテストする場合、リバースエンジニアされたコードで報告されたすべての場所を検査して、正しくない実装を確認する必要があります ([逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md))。
