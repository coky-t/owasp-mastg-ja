---
platform: ios
title: WebView でロードされた HTML でのパスワードフィールドへの参照 (References to Password Fields in WebView-Loaded HTML)
id: MASTG-TEST-0378
type: [static, code, manual]
weakness: MASWE-0034
best-practices: [MASTG-BEST-0059, MASTG-BEST-0060]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0076, MASTG-KNOW-0139]
---

## 概要

iOS アプリが `WKWebView` 内で `<input type="password">` 要素を含む HTML を描画する場合、注入された XSS ペイロードやページによってロードされたサードパーティスクリプトなど、そのページ上で実行しているあらゆる JavaScript は、`element.value` を介して入力された値を読み取ることができます。

このテストは、アプリがネイティブのセキュア入力オーバーレイを使用せずに、パスワード入力フィールドを含む HTML を `WKWebView` にロードしているかどうかをチェックします。パスワードフィールドが DOM 内に存在する場合、適切な対策は、隔離された `WKUserScript` でフォーカスを横取りし、HTML フィールドでの入力を防ぐことです。`isSecureTextEntry = true` でのネイティブ `UITextField` を同じ位置にオーバーレイして、入力された値を DOM に渡らないようにします。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [文字列の取得 (Retrieving Strings)](../../../techniques/ios/MASTG-TECH-0071.md) を使用して、バイナリの文字列テーブル内の文字列 `type="password"` や `type='password'` を検索します。

## 結果

出力にはバイナリ内でパスワードフィールドの HTML が参照されている箇所のリストを含む可能性があります。

## 評価

バイナリが `type="password"` 参照を含み、アプリがネイティブ入力オーバーレイを実装していない場合、このテストケースは不合格です。

**さらなるバリデーションが必要となります:**

[逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して報告された各コード箇所を検査します。パスワードフィールドの HTML が `WKWebView` にロードされていることを確認し、アプリがフォーカスを横取りして、該当する位置に isSecureTextEntry = true` でのネイティブ `UITextField` をオーバーレイするような `WKUserScript` を登録しているかどうかをチェックします。
