---
platform: android
title: >-
  WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in
  WebViews)
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0253
apis:
  - WebView
  - WebSettings
  - getSettings
  - setAllowFileAccess
  - setAllowFileAccessFromFileURLs
  - setAllowUniversalAccessFromFileURLs
type:
  - dynamic
  - hooks
  - manual
weakness: MASWE-0069
best-practices:
  - MASTG-BEST-0010
  - MASTG-BEST-0011
  - MASTG-BEST-0012
profiles:
  - L1
  - L2
knowledge:
  - MASTG-KNOW-0018
---

# MASTG-TEST-0253 WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)

### 概要

このテストは [WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)](MASTG-TEST-0252.md) と対をなす動的テストです。

この場合には以下のいずれかのアプローチをとることができます。

* アプリ内の `WebView` インスタンスを列挙して、その設定値をリストします。
* または、`WebView` 設定の以下のようなセッターを明示的にフックします。
  * `setJavaScriptEnabled`
  * `setAllowFileAccess`
  * `setAllowFileAccessFromFileURLs`
  * `setAllowUniversalAccessFromFileURLs`

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

### 結果

出力には、各呼び出しの引数の値やバックトレースなど、WebView 設定呼び出しのリストを含む可能性があります。

### 評価

以下のすべてが当てはまる場合、そのテストケースは不合格です ([異なる Android バージョン間での API の動作](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-local-file-access-settings) に基づいています)。

* `setJavaScriptEnabled` が明示的に `true` に設定されている。
* `setAllowFileAccess` が明示的に `true` に設定されている (または、`minSdkVersion` < 30 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。
* `setAllowFileAccessFromFileURLs` または `setAllowUniversalAccessFromFileURLs` のいずれかが明示的に `true` に設定されている (または、`minSdkVersion` < 16 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。

**さらなるバリデーションが必要となります:**

フック出力からのバックトレースを使用して、[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0023.md) を使用して、以下のようなコード箇所を検査します。

* その設定が明示的に使用され、特定した値に構成されているかどうかを判断します。
* どの `WebView` インスタンスがその構成を受け取り、機密情報や機能を扱っているかどうかを判断します。
* `WebView` が、たとえば `loadUrl("file://...")` または、`loadDataWithBaseURL` を `file://` ベース URL とともに用いて、ローカル `file://` コンテンツをロードするかどうかを判断します。

特定した WebView について、攻撃者が制御する JavaScript が、HTML インジェクション、JavaScript インジェクション、またはその他の信頼できないコンテンツを介して、ローカルファイルコンテンツで実行するかどうかを判断します。また、攻撃者が `file://` URL を介してアクセス可能なローカルファイルやその他の機密データを流出する可能性があるかどうかも判断します。

> \[!NOTE] `AllowFileAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。
