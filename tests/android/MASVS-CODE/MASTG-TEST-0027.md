---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: WebView での URL ローディングのテスト (Testing for URL Loading in WebViews)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

[WebView での URL ローディング](../../../Document/0x05h-Testing-Platform-Interaction.md#url-loading-in-webviews "URL Loading in WebViews") をテストするには、特にユーザーが信頼できる環境から移動できる可能性がある場合に、 [ページナビゲーションの処理](https://developer.android.com/guide/webapps/webview#HandlingNavigation "Handling page navigation") を注意深く分析する必要があります。Android でのデフォルトで最も安全な動作は、ユーザーが WebView 内でクリックする可能性のあるリンクをデフォルトのウェブブラウザで開くようにすることです。しかし、このデフォルトのロジックはナビゲーションリクエストをアプリ自体で処理できるように `WebViewClient` を構成することで変更できます。

## 静的解析

### ページナビゲーション処理のオーバーライドのチェック

アプリが `WebViewClient` を構成してデフォルトのページナビゲーションロジックをオーバーライドしているかどうかをテストするには、以下のインターセプトコールバック関数を探して検査する必要があります。

- `shouldOverrideUrlLoading` ではアプリケーションは `true` を返して疑わしいコンテンツでの WebView のローディングを中止するか、`false` を返して WebView が URL をロードできます。以下を考慮します。
    - このメソッドは POST リクエストに対しては呼び出されません。
    - このメソッドは XmlHttpRequests, iFrames, HTML や `<script>` タグの "src" 属性に対しては呼び出されません。代わりに `shouldInterceptRequest` がこの処理を行う必要があります。
- `shouldInterceptRequest` ではアプリケーションはリソースリクエストからデータを返すことができます。返り値が null の場合、WebView は通常通りリソースのロードを続行するでしょう。それ以外の場合、`shouldInterceptRequest` メソッドによって返されたデータが使用されます。以下を考慮します。
    - このコールバックはネットワーク経由でリクエストを送信するスキームだけでなく、さまざまな URL スキーム (`http(s):`, `data:`, `file:` など) に対して呼び出されます。
    - これは `javascript:` や `blob:` URL や、`file:///android_asset/` や `file:///android_res/` を介してアクセスされるアセットに対しては呼び出されません。
  リダイレクトの場合、これは最初のリソース URL に対してのみ呼び出され、それ以降のリダイレクト URL に対しては呼び出されません。
    - セーフブラウジングが有効になっている場合でも、これらの URL はセーフブラウジングチェックを受けますが、開発者は `setSafeBrowsingWhitelist` で URL を許可したり `onSafeBrowsingHit` コールバックを介して警告を無視できます。

ご覧のように、WebViewClient が構成されている WebView のセキュリティをテストする際に考慮すべき点が多数あります。そのため [`WebViewClient` ドキュメント](https://developer.android.com/reference/android/webkit/WebViewClient "WebViewClient") をチェックして、そのすべてを注意深く読んで理解してください。

### EnableSafeBrowsing 無効化のチェック

`EnableSafeBrowsing` のデフォルト値は `true` ですが、アプリケーションによってはこれを無効にすることを選択することがあります。SafeBrowsing が有効になっていることを検証するには、AndroidManifest.xml ファイルを検査し、以下の設定が存在しないことを確認します。

```xml
<manifest>
    <application>
        <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
                   android:value="false" />
        ...
    </application>
</manifest>
```

## 動的解析

ディープリンクを動的にテストする便利な方法は、アプリを使用して WebView 内のリンクをクリックしている間に Frida または frida-trace を使用して `shouldOverrideUrlLoading`, `shouldInterceptRequest` メソッドをフックすることです。 `getHost`, `getScheme`, `getPath` など、他の関連する [`Uri`](https://developer.android.com/reference/android/net/Uri "Uri class") メソッドもフックしてください。これらは一般的にリクエストを検査し、既知のパターンや拒否リストと照合するために使用されます。
