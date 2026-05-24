---
platform: android
title: WebView におけるコンテンツプロバイダアクセス API の実行時使用 (Runtime Use of Content Provider Access APIs in WebViews)
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0251
apis: [WebView, WebSettings, getSettings, ContentProvider, setAllowContentAccess, setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled]
type: [dynamic, hooks, manual]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0018]
---

## 概要

このテストは [WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)](MASTG-TEST-0250.md) と対をなす動的テストです。

この場合、関連する API をフックまたはトレースする際、以下の二つのアプローチをとることができます。

- アプリの `WebView` のインスタンスを列挙し、その設定値をリストします。
- または、`WebView` 設定のセッターを明示的にフックします。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力には WebView インスタンスと対応する設定のリストを含む可能性があります。

## 評価

以下のすべてが当てはまる場合、そのテストケースは不合格です。

- `JavaScriptEnabled` が `true` である。
- `AllowContentAccess` が `true` である。
- `AllowUniversalAccessFromFileURLs` が `true` である。

**さらなるバリデーションが必要となります:**

フック出力からのバックトレースを使用して、[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md) を使用して、以下のようなコード箇所を検査します。

- その設定が明示的に使用され、特定した値に構成されているかどうかを判断します。
- どの `WebView` インスタンスがその構成を受け取り、機密情報や機能を扱っているかどうかを判断します。
- `WebView` が、コンテンツプロバイダのデータが `content://` URL を介してアクセスできるコンテキストでコンテンツをロードしているかどうかを判断します。

特定した WebView について、攻撃者が制御する JavaScript が、機密データを扱うコンテンツプロバイダにアクセスできるコンテキストで実行する可能性があるかどうかを判断します。また [WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)](MASTG-TEST-0250.md) で取得したコンテンツプロバイダのリストを使用して、それが機密データを取り扱っているかどうかを検証する必要があります。

> [!NOTE]
> `AllowContentAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。
