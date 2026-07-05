---
platform: ios
title: WebView での過度に広範なファイル読み取りアクセス (Overly Broad File Read Access in WebViews)
id: MASTG-TEST-0333
type:
  - static
  - code
  - manual
weakness: MASWE-0069
best-practices:
  - MASTG-BEST-0033
knowledge:
  - MASTG-KNOW-0076
profiles:
  - L1
  - L2
---

# MASTG-TEST-0333 WebView での過度に広範なファイル読み取りアクセス (Overly Broad File Read Access in WebViews)

### 概要

iOS アプリは [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl\(_:allowingreadaccessto:\)) を使用して [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) にローカルファイルをロードできます。

このテストはアプリが `loadFileURL(_:allowingReadAccessTo:)` を過度に広範な `readAccessURL` で使用しているかどうかをチェックします。攻撃者が制御する入力が、ロードされるファイル URL に影響し、読み取りアクセス範囲が広すぎる場合、WebView はアプリコンテナ内の機密ファイルにアクセスできる可能性があります。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力にはバイナリ内で `WKWebView.loadFileURL(_:allowingReadAccessTo:)` が呼び出される場所のリストを含む可能性があります。

### 評価

`loadFileURL(_:allowingReadAccessTo:)` への呼び出しにおいて `readAccessURL` 引数が過度に広範な読み取りアクセス (たとえば `Documents` ディレクトリ全体や、アプリコンテナのルートなど) を付与している場合、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査します。

* `fileURL` 引数を検査し、攻撃者が制御する入力によって影響される可能性があるかどうかを判断します。
* `readAccessURL` 引数を検査し、必要以上に広範なアクセスを付与しているかどうかを判断します。
* 許可される読み取り範囲が、意図したコンテンツに必要な最小限のディレクトリに制限されていることを検証します。
