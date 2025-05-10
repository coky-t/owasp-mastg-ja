---
title: WebView で JavaScript を無効にする (Disable JavaScript in WebViews)
alias: disable-javascript-in-webviews
id: MASTG-BEST-0012
platform: android
---

JavaScript が **必要ではない** 場合は、[`setJavaScriptEnabled(false)`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29) を設定して、WebView で明示的に無効にします。

WebView で JavaScript を有効にすると、**攻撃対象領域が拡大** し、アプリが以下のような重大なセキュリティリスクにさらされる可能性があります。

- **[Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/):** 悪意のある JavaScript が WebView 内で実行され、セッションハイジャック、クレデンシャル窃取、改竄につながる可能性があります。
- **データ流出:** WebView は Cookie、トークン、ローカルファイルなどの機密データに (`setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, または `setAllowContentAccess(true)` が有効になっている場合は `file://` または `content://` URI で経由して) アクセスできます。`setAllowUniversalAccessFromFileURLs(true)` が設定されている場合は、悪意のあるスクリプトによってこれらのデータが流出する可能性があります。
- **不正なデバイスアクセス:** JavaScript を `addJavascriptInterface` と組み合わせて使用すると、公開されているネイティブ Android インタフェースを悪用して、リモートコード実行 (RCE) を引き起こす可能性があります。

アプリの要件により、これが可能ではないこともあります。そのような場合には、適切な入力バリデーション、出力エンコーディング、その他のセキュリティ対策を実装していることを確認してください。

注: アプリでより安全にウェブコンテンツを表示する方法を提供する、[Trusted Web Activities](https://developer.android.com/guide/topics/app-bundle/trusted-web-activities) や [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/overview/) など、通常の WebView に代わるものを使用したいことがあります。このような場合、JavaScript はブラウザ環境内で処理され、最新のセキュリティアップデート、サンドボックス化、およびクロスサイトスクリプティング (XSS) や中間マシン (MITM) 攻撃などの一般的なウェブ脆弱性に対する緩和策の恩恵を受けることができます。
