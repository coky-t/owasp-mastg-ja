---
title: WebView でファイルコンテンツを安全にロードする (Securely Load File Content in a WebView)
alias: securely-load-file-content-in-webview
id: MASTG-BEST-0011
platform: android
knowledge: [MASTG-KNOW-0018]
---

**WebView にファイルコンテンツを安全にロードする** ための推奨されるアプローチは、[`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) と [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) を使用して、安全でない `file://` URL ではなく `https://` URL を使用してアプリのアセットディレクトリまたはリソースディレクトリからアセットをロードすることです。これにより、コンテンツが安全な同一オリジン環境でロードされることを確保し、ローカルファイルがクロスオリジン攻撃にさらされる可能性を回避します。

WebView が `file://` を使用してローカルファイルをロードすることを許可しなければならない場合には、以下を考慮してください。

- WebView のファイルアクセスメソッドに安全なデフォルトがある `minSdkVersion` を持つアプリでは、これらのメソッドが **使用されていない** こと、およびデフォルト値が保持されていることを確認します。もしくは、明示的に `false` を設定してして、WebView がローカルファイルアクセスを許可しないようにします。
    - `setAllowFileAccess(false)`
    - `setAllowFileAccessFromFileURLs(false)`
    - `setAllowUniversalAccessFromFileURLs(false)`

- これらのメソッドに対して **安全なデフォルトがない**  (古い API レベルなど) `minSdkVersion` を持つアプリでは、上記のメソッドが WebView 構成で **明示的に** `false` に設定されていることを確認します。

詳細については、[ローカルコンテンツを安全にロードするための公式 Android ドキュメント](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content)、特に ["非推奨事項"](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content#antipatterns) のセクションを参照してください。
