---
platform: android
title: WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0253
apis: [WebView, WebSettings, getSettings, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [dynamic]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0010, MASTG-BEST-0011, MASTG-BEST-0012]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0018]
---

## 概要

このテストは [WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)](MASTG-TEST-0252.md) と対をなす動的テストです。

## 手順

1. [Frida (Android)](../../../tools/android/MASTG-TOOL-0001.md) などの動的解析ツールを実行して、以下のいずれかを実行します。
    - アプリ内の `WebView` インスタンスを列挙して、その設定値をリストする
    - または、`WebView` 設定の以下のようなセッターを明示的にフックする
        - `setJavaScriptEnabled`
        - `setAllowFileAccess`
        - `setAllowFileAccessFromFileURLs`
        - `setAllowUniversalAccessFromFileURLs`

## 結果

出力には WebView インスタンスと対応する設定のリストを含む可能性があります。

## 評価

以下のすべてが当てはまる場合、そのテストケースは不合格です ([異なる Android バージョン間での API の動作](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-local-file-access-settings) に基づいています)。

- `setJavaScriptEnabled` が明示的に `true` に設定されている。
- `setAllowFileAccess` が明示的に `true` に設定されている (または、`minSdkVersion` < 30 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。
- `setAllowFileAccessFromFileURLs` または `setAllowUniversalAccessFromFileURLs` のいずれかが明示的に `true` に設定されている (または、`minSdkVersion` < 16 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。

> [!NOTE]
> `AllowFileAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。
