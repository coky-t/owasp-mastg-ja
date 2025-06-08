---
platform: android
title: WebView におけるコンテンツプロバイダアクセス API の実行時使用 (Runtime Use of Content Provider Access APIs in WebViews)
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0251
apis: [WebView, WebSettings, getSettings, ContentProvider, setAllowContentAccess, setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled]
type: [dynamic]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013]
profiles: [L1, L2]
---

## 概要

このテストは [WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)](MASTG-TEST-0250.md) と対をなす動的テストです。

## 手順

1. [Frida for iOS](../../../tools/ios/MASTG-TOOL-0039.md) などの動的解析ツールを実行して、以下のいずれかを実行します。
    - アプリ内の `WebView` インスタンスを列挙して、その設定値をリストする
    - または、`WebView` 設定のセッターを明示的にフックする

## 結果

出力には WebView インスタンスと対応する設定のリストを含む可能性があります。

## 評価

**不合格:**

以下のすべてが当てはまる場合、そのテストは不合格です。

- `JavaScriptEnabled` が `true` である。
- `AllowContentAccess` が `true` である。
- `AllowUniversalAccessFromFileURLs` が `true` である。

[WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)](MASTG-TEST-0250.md) で取得したコンテンツプロバイダのリストを使用して、それが機密データを取り扱っているかどうかを検証する必要があります。

**注:** `AllowContentAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。したがって、アプリがコンテンツプロバイダにアクセスする必要がない場合は、明示的に `false` を設定することをお勧めします。

**合格:**

以下のいずれかが当てはまる場合、そのテストは合格です。

- `JavaScriptEnabled` が `false` である。
- `AllowContentAccess` が `false` である。
- `AllowUniversalAccessFromFileURLs` が `false` である。
