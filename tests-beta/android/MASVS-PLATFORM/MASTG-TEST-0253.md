---
platform: android
title: WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0253
apis: [WebView, WebSettings, getSettings, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [dynamic]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0010, MASTG-BEST-0011, MASTG-BEST-0012]
status: new
---

## 概要

このテストは [WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)](MASTG-TEST-0252.md) と対をなす動的テストです。

## 手順

1. [Frida for iOS](../../../tools/ios/MASTG-TOOL-0039.md) などの動的解析ツールを実行して、以下のいずれかを実行します。
    - アプリ内の `WebView` インスタンスを列挙して、その設定値をリストする
    - または、`WebView` 設定のセッターを明示的にフックする

## 結果

出力には WebView インスタンスと対応する設定のリストを含む可能性があります。

## 評価

**不合格:**

以下のすべてが当てはまる場合、そのテストは不合格です。

- `AllowFileAccess` が `true` である。
- `AllowFileAccessFromFileURLs` が `true` である。
- `AllowUniversalAccessFromFileURLs` が `true` である。

**注:** `AllowFileAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。したがって、アプリがローカルファイルにアクセスする必要がない場合は、明示的に `false` を設定することをお勧めします。

**合格:**

以下のいずれかが当てはまる場合、そのテストは合格です。

- `AllowFileAccess` が `false` である。
- `AllowFileAccessFromFileURLs` が `false` である。
- `AllowUniversalAccessFromFileURLs` が `false` である。
