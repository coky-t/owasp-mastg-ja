---
masvs_v1_id:
- MSTG-PLATFORM-5
masvs_v2_id:
- MASVS-PLATFORM-2
platform: android
title: WebView での JavaScript 実行のテスト (Testing JavaScript Execution in WebViews)
masvs_v1_levels:
- L1
- L2
---

## 概要

[WebView での JavaScript 実行](../../../Document/0x05h-Testing-Platform-Interaction.md#javascript-execution-in-webviews "JavaScript Execution in WebViews") をテストするには、アプリの WebView 使用をチェックし、各 WebView が JavaScript 実行を許可するかどうかを評価します。アプリが正常に機能するために JavaScript 実行が必要な場合には、アプリがすべてのベストプラクティスに従っていることを確認する必要があります。

## 静的解析

WebView を作成して使用するには、アプリは `WebView` クラスのインスタンスを作成しなければなりません。

```java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("https://www.owasp.org/");
```

WebView にはさまざまな設定を適用できます (JavaScript の有効化/無効化はその一例です)。WebView では JavaScript はデフォルトで無効になっているため、明示的に有効にしなければなりません。[`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled%28boolean%29 "setJavaScriptEnabled in WebViews") メソッドを探して、JavaScript の有効化をチェックします。

```java
webview.getSettings().setJavaScriptEnabled(true);
```

これは WebView が JavaScript を解釈できるようにします。アプリの攻撃対象領域を減らすために必要な場合にのみ有効にすべきです。JavaScript が必要な場合は、以下を確認すべきです。

- エンドポイントへの通信は一貫して HTTPS (または暗号化が可能な他のプロトコル) に依存し、送信時に HTML と JavaScript を改竄から保護します。
- JavaScript と HTML はアプリのデータディレクトリ内からローカルに、または信頼できるウェブサーバーからのみロードされます。
- ユーザーは、ユーザーが提供した入力に基づいてさまざまなリソースをロードする手段によって、ロードするソースを定義することはできません。

すべての JavaScript ソースコードとローカルに保存されたデータを削除するには、アプリを閉じるときに [`clearCache`](https://developer.android.com/reference/android/webkit/WebView#clearCache%28boolean%29 "clearCache in WebViews") で WebView のキャッシュをクリアします。

Android 4.4 (API レベル 19) より古いプラットフォームを実行しているデバイスでは、いくつかのセキュリティ上の問題があるバージョンの WebKit を使用します。回避策として、これらのデバイスでアプリが動作する場合、アプリは WebView オブジェクトが [信頼できるコンテンツのみを表示する](https://developer.android.com/training/articles/security-tips.html#WebView "WebView Best Practices") ことを確認しなければなりません。

## 動的解析

動的解析は動作条件に依存します。アプリの WebView に JavaScript を注入する方法はいくつかあります。

- エンドポイントにクロスサイトスクリプティングの脆弱性を保存します。ユーザーが脆弱な機能に移動すると、エクスプロイトがモバイルアプリの WebView に送信されます。
- 攻撃者は [中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) に位置取りし、JavaScript を注入してレスポンスを改竄します。
- マルウェアは WebView によってロードされるローカルファイルを改竄します。

これらの攻撃ベクトルに対処するには、以下をチェックします。

- エンドポイントが提供するすべての機能に [蓄積型 XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting "Stored Cross-Site Scripting") がない。
- アプリのデータディレクトリにあるファイルのみが WebView でレンダリングされる (テストケース「WebView でのローカルファイルインクルージョンのテスト」を参照)。

- HTTPS 通信は MITM 攻撃を避けるためのベストプラクティスに従って実装されなければなりません。つまり、以下のようになります。
    - すべての通信は TLS で暗号化されます。
    - 証明書は適切にチェックされます。
    - 証明書はピン留めされるべきです。
