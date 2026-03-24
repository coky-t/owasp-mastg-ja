---
platform: ios
title: 非推奨の WebView API の使用 (Use of Deprecated WebView APIs)
id: MASTG-TEST-0331
type: [static]
available_since: 2.0
deprecated_since: 12.0
weakness: MASWE-0072
profiles: [L1, L2]
best-practices: [MASTG-BEST-0032]
knowledge: [MASTG-KNOW-0076]
---

## 概要

このテストでは、`UIWebView` ([WebView (WebViews)](../../../knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076.md)) への参照を探します。これは iOS 12.0 以降非推奨となったコンポーネントであり、`WKWebView` が好まれます。`UIWebView` はセキュリティとパフォーマンスのリスクがあります。JavaScript を完全に無効化できず、プロセス分離 (`WKWebView` が提供) がなく、Content Security Policy (CSP) などの現代のウェブセキュリティ機能をサポートしていません。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) の説明に従ってアプリを抽出します。
2. すべての実行ファイルとライブラリに対して [アプリケーションバイナリから情報の抽出 (Extracting Information from the Application Binary)](../../../techniques/ios/MASTG-TECH-0070.md) を使用して、アプリの `UIWebView` への参照を探します。

## 結果

出力には `UIWebView` が使用されている場所のリストを含む可能性があります。

## 評価

アプリに `UIWebView` の使用が見つかった場合、そのテストケースは不合格です。
