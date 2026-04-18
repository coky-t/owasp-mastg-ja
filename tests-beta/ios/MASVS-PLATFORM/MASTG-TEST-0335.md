---
platform: ios
title: 設定により緩和される WebView のファイルオリジンアクセス (WebView File Origin Access Relaxed by Configuration)
id: MASTG-TEST-0335
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0033]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0076]
---

## 概要

`WKWebView` は、`file://` オリジンから実行する JavaScript が他のリソースにアクセスする方法に作用する設定をサポートしています。具体的には、`allowFileAccessFromFileURLs` は `file://` URL のコンテキストで実行する JavaScript が他の `file://` URL からのコンテンツにアクセスできるようにし、`allowUniversalAccessFromFileURLs` は `file://` URL のコンテキストで実行する JavaScript が任意のオリジンからのコンテンツにアクセスできるようにします。どちらの設定も有効にすると危険とみなされます。なぜなら、通常ローカルコンテンツに適用するオリジン制限を緩和するため、クロスサイトスクリプティング (XSS) やローカルファイルインクルージョン (LFI) などの脆弱性のリスクを高め、データ抽出やその他の悪意のあるアクションにつながるためです。

このテストはアプリが任意の `WKWebView` インスタンスに対してこれらの設定のいずれかを有効にしているかどうかをチェックします。iOS では、これらの設定は一般的に非公開またはサポートされていないパスを通じて、たとえば `WKPreferences` または `WKWebViewConfiguration` に対して `setValue:forKey:` または同等の Swift 呼び出しを介してキー値コーディングを使用することによって、アクセスされます。

アプリが明示的に [`WKWebViewPreferences.setJavaScriptEnabled`](https://developer.apple.com/documentation/webkit/wkpreferences/javascriptenabled) (iOS 14 以降非推奨) または [`WKWebpagePreferences.allowsContentJavaScript`](https://developer.apple.com/documentation/webkit/wkwebpagepreferences/allowscontentjavascript) を `false` に設定しない限り、JavaScript はデフォルトで有効になっていることに注意してください。

このテストは、`loadFileURL(_:allowingReadAccessTo:)` を通じて WebView に付与される **ネイティブファイルシステム読み取りスコープ** に焦点を当てた、[WebView での過度に広範なファイル読み取りアクセス (Overly Broad File Read Access in WebViews)](MASTG-TEST-0333.md) と関連していますが、異なるものです。対照的に、このテストは `file://` URL からロードしたコンテンツに対する **JavaScript オリジン制限** に焦点を当てています。ファイル読み取りスコープが正しく制限されている場合でも、`allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` を有効にすると、ローカルページで実行している JavaScript (例: `fetch()`, `XMLHttpRequest`) が追加のリソースにアクセスしたり、リモートオリジンと通信することが可能になります。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) の説明に従ってアプリを抽出します。
2. アプリバイナリに対して [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行し、関連する設定値への参照を探します。

## 結果

出力にはアプリが関連する設定値を参照または有効にしているバイナリ内の場所を特定する可能性があります。

## 評価

ローカル `file://` コンテンツをロードする `WKWebView` に対してアプリが `allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` を有効にしている場合、そのテストケースは不合格です。

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して、報告された各呼び出し箇所を検査します。

- `allowFileAccessFromFileURLs` または `allowUniversalAccessFromFileURLs` が明示的に使用され、たとえば `setValue:forKey:` や同等の Swift 呼び出しを使用して、`true` に設定されているかどうかを判断します。
- どの `WKWebView` インスタンスがその設定を受け取り、それが機密情報や機能を扱っているかどうかを判断します。
- その `WKWebView` が、たとえば `loadFileURL(_:allowingReadAccessTo:)` や `loadHTMLString(_:baseURL:)` などの API を `file://` ベース URL とともに使用して、ローカル `file://` コンテンツをロードするかどうかを判断します。

一部のアプリでは `allowFileAccessFromFileURLs` や `allowUniversalAccessFromFileURLs` を設定するために変数や設定ロジックを使用していることがあり、静的解析だけでは特定するのが難しいことがあることに留意します。動的解析は実行時にその設定が有効になっているかどうかを確認するのに役立ちます。

特定された WebView について、たとえば HTML インジェクション、JavaScript インジェクション、またはその他の信頼できないコンテンツを通じて、攻撃者が制御する JavaScript がローカルページコンテキストで実行する可能性があるかどうかを判断します。また、たとえば `fetch` や `XMLHttpRequest` を使用してリモートサーバーに送信したり、画像や iframe などの外部リソースへのリクエストに埋め込むことによって、攻撃者がアクセスしたデータを抽出する可能性があるかどうかも判断します。
