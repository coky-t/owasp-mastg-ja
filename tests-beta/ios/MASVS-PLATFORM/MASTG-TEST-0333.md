---
platform: ios
title: WebView での過度に広範なファイル読み取りアクセス (Overly Broad File Read Access in WebViews)
id: MASTG-TEST-0333
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0033]
knowledge: [MASTG-KNOW-0076]
profiles: [L1, L2]
---

## 概要

iOS アプリは [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:)) を使用して [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) にローカルファイルをロードできます。

このテストはアプリが `loadFileURL(_:allowingReadAccessTo:)` を過度に広範な `readAccessURL` で使用しているかどうかをチェックします。攻撃者が制御する入力が、ロードされるファイル URL に影響し、読み取りアクセス範囲が広すぎる場合、WebView はアプリコンテナ内の機密ファイルにアクセスできる可能性があります。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) の説明に従ってアプリを抽出します。
2. アプリバイナリに対して [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行し、`WKWebView.loadFileURL(_:allowingReadAccessTo:)` への呼び出しを探します。

## 結果

出力にはバイナリ内で `WKWebView.loadFileURL(_:allowingReadAccessTo:)` が呼び出される場所のリストを含む可能性があります。

## 評価

`loadFileURL(_:allowingReadAccessTo:)` への呼び出しにおいて `readAccessURL` 引数が過度に広範な読み取りアクセス (たとえば `Documents` ディレクトリ全体や、アプリコンテナのルートなど) を付与している場合、そのテストケースは不合格です。

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して、報告された各呼び出し箇所を検査します。

- `fileURL` 引数を検査し、攻撃者が制御する入力によって影響される可能性があるかどうかを判断します。
- `readAccessURL` 引数を検査し、必要以上に広範なアクセスを付与しているかどうかを判断します。
- 許可される読み取り範囲が、意図したコンテンツに必要な最小限のディレクトリに制限されていることを検証します。

`loadFileURL(_:allowingReadAccessTo:)` のすべての使用が `readAccessURL` を最小限の範囲に制限し、攻撃者が影響したファイルローディングが、意図しないファイルに到達できない場合、そのテストは合格です。
