---
platform: ios
title: WebView のファイルオリジンポリシーを緩和する実行時設定 (Runtime Setting of Relaxed WebView File Origin Policies)
id: MASTG-TEST-0336
type: [dynamic]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0033]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0076]
---

## 概要

このテストは [設定により緩和される WebView のファイルオリジンアクセス (WebView File Origin Access Relaxed by Configuration)](MASTG-TEST-0335.md) と対をなす動的テストです。

`WKWebView` は `file://` オリジンから実行する JavaScript が他のリソースにアクセスする方法に影響する設定をサポートします。特に、`allowFileAccessFromFileURLs` は `file://` URL のコンテキストで実行する JavaScript が他の `file://` URL からのコンテンツにアクセスできるようにし、`allowUniversalAccessFromFileURLs` は `file://` URL のコンテキストで実行する JavaScript が任意のオリジンからのコンテンツにアクセスできるようにします。どちらの設定も、通常ではローカルコンテンツに適用するオリジン制限を緩和するため、有効にすると危険です。

このテストは、ローカル `file://` コンテンツをロードする `WKWebView` に対して、アプリケーションがこれらのせっていのいずれかを有効にしているかどうかを実行時に検証します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md) で説明されているように、アプリをデバイスやシミュレータにデプロイします。
2. [Frida (iOS)](../../../tools/ios/MASTG-TOOL-0039.md) などの実行時計装ツールでアプリを起動します。
3. 関連する WebKit API をフックして、アプリが緩和されたファイルオリジンポリシーを有効にし、ローカルコンテンツを `WKWebView` にロードするかどうかを確認します。
4. `WKWebView` を作成および構成するコードパスをトリガーします。
5. キャプチャしたランタイム引数を検査します。

監視する代表的な API は以下のとおりです。

- `WKPreferences _setAllowFileAccessFromFileURLs:`
- `WKWebViewConfiguration _setAllowUniversalAccessFromFileURLs:`
- `WKPreferences setJavaScriptEnabled:`
- `WKWebView loadFileURL:allowingReadAccessToURL:`
- `WKWebView loadHTMLString:baseURL:` (`file://` ベース URL が使用される可能性がある場合)

## 結果

出力には、アプリケーションが実行時に `allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` を有効にしているかどうか、および影響を受ける `WKWebView` がローカル `file://` コンテンツをロードするかどうかを示す可能性があります。

## 評価

ローカル `file://` コンテンツをロードする `WKWebView` に対して、アプリケーションが `allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` を有効にしている場合、そのテストケースは不合格です。

[逆アセンブルされたネイティブコードのレビュー (Reviewing Disassembled Native Code)](../../../techniques/ios/MASTG-TECH-0077.md) を使用して、報告された各呼び出し箇所を検査します。

- `allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` が明示的に使用され、`true` に設定しているかどうかを判断します。
- どの `WKWebView` インスタンスがその設定を受け取り、機密情報や機能を取り扱っているかどうかを判断します。
- その `WKWebView` が、たとえば `loadFileURL(_:allowingReadAccessTo:)` や `loadHTMLString(_:baseURL:)` などの API を `file://` ベース URL とともに使用して、ローカル `file://` コンテンツをロードするかどうかを判断します。

一部のアプリではこれらの値を設定するために変数や構成ロジックを使用することがあり、静的解析だけでは特定することが困難となる可能性があることに留意します。動的解析は実行時に設定が有効になっているかどうかを確認するのに役立ちます。

特定された WebView については、たとえば HTML インジェクション、JavaScript インジェクション、他の信頼できないコンテンツなど、攻撃者が制御する JavaScript がローカルページコンテキストで実行する可能性があるかどうかを判断します。また、たとえば `fetch` や `XMLHttpRequest` を使用してリモートサーバーに送信したり、image や iframe などの外部リソースへのリクエストに埋め込むことにより、攻撃者がアクセスしたデータを流出するかどうかも判断します。

悪用可能性が完全に確認できない場合でも、これらの設定は `file://` コンテンツに通常適用されるオリジン分離を弱めるため、削除することをお勧めします。これらを有効にすると、コンテンツインジェクションや信頼できない入力の不適切な処理など、他の WebView の脆弱性の影響を増大します。
