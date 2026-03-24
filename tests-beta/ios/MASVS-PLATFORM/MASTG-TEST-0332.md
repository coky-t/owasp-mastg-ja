---
platform: ios
title: WebView での攻撃者制御の URI (Attacker-Controlled URI in WebViews)
id: MASTG-TEST-0332
type: [static]
weakness: MASWE-0071
best-practices: [MASTG-BEST-0034]
profiles: [L1, L2, P]
knowledge: [MASTG-KNOW-0076]
---

## 概要

iOS アプリはさまざまな URL ロードメソッドを使用して [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) にコンテンツを動的にロードできます。これらのメソッドはリモートウェブコンテンツとローカルに保存されたファイルの両方を描画できます。

信頼できない入力を処理する場合、以下のような WKWebView API が一般的にターゲットとなります。

**リモート URL ローディング:**

- [`load(_:)`](https://developer.apple.com/documentation/webkit/wkwebview/load(_:))
- [`load(_:mimeType:characterEncodingName:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/load(_:mimetype:characterencodingname:baseurl:))

**ローカル URL およびコンテンツのローディング:**

- [`loadFileRequest(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfilerequest(_:allowingreadaccessto:))
- [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:))
- [`loadHTMLString(_:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadhtmlstring(_:baseurl:))

そのソースに関わらず、攻撃者が制御する入力 (たとえば、ディープリンク、カスタム URL スキーム、UI からのユーザー提供データを通じて) に由来する URL を `WKWebView` URL ロードメソッドに直接渡すと、不正なリダイレクト、クロスサイトスクリプティング (XSS)、ローカルファイルの露出といった脆弱性につながる可能性があります。

このテストはアプリが適切な URL バリデーションなしで攻撃者が制御する入力を `WKWebView` URL ロード API に渡しているかどうかをチェックします。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) の説明に従ってアプリを抽出します。
2. アプリバイナリに対して [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行し、`WKWebView` URL ロード API への呼び出しを探します。

## 結果

出力にはバイナリ内で `WKWebView` URL ロード API が呼び出される場所のリストを含む可能性があります。

## 評価

`WKWebView` URL ロード API への呼び出しが、適切なバリデーションなしで攻撃者が制御する入力に由来する URL で見つかった場合、そのテストケースは不合格です。

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査します。

- URL の由来を追跡します。
- URL が攻撃者によって制御された入力 (たとえば、カスタム URL スキームパラメータ、ディープリンクコンポーネント、UI からのサニタイズされていないユーザー入力) に由来するかどうかを判断します。
- URL が `WKWebView` URL ロード API に渡される前に適切に検証されていることを確認します。
