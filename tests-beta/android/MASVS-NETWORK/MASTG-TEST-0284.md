---
title: WebView での正しくない SSL エラー処理 (Incorrect SSL Error Handling in WebViews)
platform: android
id: MASTG-TEST-0284
type: [static]
weakness: MASWE-0052
best-practices: [MASTG-BEST-0021]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0010]
---

## 概要

このテストは、Android アプリが適切なバリデーションなしで [`onReceivedSslError(...)`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError%28android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError%29) メソッドをオーバーライドして、SSL/TLS 証明書エラーを無視する WebView を有しているかどうかを評価します。

`onReceivedSslError(...)` メソッドは `WebView` がページをロード時に SSL 証明書エラーに遭遇すると呼び出されます。デフォルトでは、`WebView` は安全でない接続からユーザーを保護するためにリクエストをキャンセルします。このメソッドをオーバーライドして、適切なバリデーションなしで [`SslErrorHandler.proceed()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#proceed%28%29) を呼び出すと、これらの保護を無効にします。

これは事実上 `WebView` での SSL 証明書チェックをバイパスし、無効、期限切れ、または自己署名の証明書を使用した [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) にアプリをさらすことになります。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. ソースコードを検査し、静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行し、`onReceivedSslError(...)` のすべての使用箇所を探します。

## 結果

出力には SSL エラーを適切に処理する例外処理なしで `proceed()` を含む `onReceivedSslError(...)` が使用されている場所のリストを含みます。

## 評価

`onReceivedSslError(...)` がオーバーライドされ、適切なバリデーションやユーザーの関与なしで証明書エラーが無視される場合、そのテストは不合格です。

これには以下のようなケースを含みます。

- **SSL エラーを無条件に受け入れること:** エラーの性質をチェックせずに `proceed()` を呼び出します。
- **プライマリエラーコードのみに依存すること:** プライマリエラーが `SSL_UNTRUSTED` でない場合に処理を続行するといった意思決定に [`getPrimaryError()`](https://developer.android.com/reference/android/net/http/SslError#getPrimaryError()) を使用すると、チェーン内の追加のエラーを見逃す可能性があります。
- **例外をサイレントに抑制すること:** [`cancel()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#cancel()) を呼び出さずに `onReceivedSslError(...)` で例外をキャッチすることで、接続をサイレントに継続できます。

[公式の Android ガイダンス](https://developer.android.com/reference/android/webkit/WebViewClient.html#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)) によると、アプリは SSL エラーに応答して `proceed()` を呼び出すべきではありません。正しい動作は、潜在的に安全でない接続からユーザーを保護するために、リクエストをキャンセルすることです。また、ユーザーは SSL の問題を確実に評価できないため、ユーザープロンプトも推奨されません。

自動化ツールを使用してテストする場合、リバースエンジニアされたコードで報告されたすべての場所を検査して、正しくない実装を確認する必要があります ([逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md))。
