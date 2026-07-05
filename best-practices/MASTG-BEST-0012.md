---
title: WebView で JavaScript を無効にする (Disable JavaScript in WebViews)
alias: disable-javascript-in-webviews
id: MASTG-BEST-0012
platform: android
knowledge: [MASTG-KNOW-0018]
---

JavaScript を有効にすることは **それ自体としては脆弱性ではありません**。実際のアプリでは、現代のウェブアプリケーション、インタラクティブなアカウントポータル、サポートセンター、決済、ログインフロー、ウェブテクノロジで構築されたハイブリッドアプリコンテンツを描画するなど、正当な機能に必要とされることがよくあります。Ionic や Capacitor といったフレームワークは JavaScript アプリケーションコードを実行する WebView を中心に構築されており、`react-native-webview` はウェブコンテンツをネイティブビューに描画するために特化して存在します。

Android のガイダンスは JavaScript を有効にした WebView の安全でない使用を [クロスアプリスクリプティング](https://developer.android.com/privacy-and-security/risks/cross-app-scripting) と関連付けています。JavaScript は WebView の攻撃対象領域を増やしますが、深刻なケースは一般的に次の条件のいずれかまたは複数と組み合わされた時に発生します: 信頼できないコンテンツや十分に検証されていないコンテンツのロード、JavaScript ブリッジの露出、ファイルやコンテンツへの自由なアクセスの許可、安全でない URL ローディングの使用。

## 必要でない場合には WebView で JavaScript を無効のままとする

JavaScript は [WebViews ではデフォルトで無効にされています](https://developer.android.com/develop/ui/views/layout/webapps/webview#EnablingJavaScript)。JavaScript が必要でない場合は、最初から有効にしないか、WebView で [`setJavaScriptEnabled(false)`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29) を用いて [明示的に無効にします](https://developer.android.com/privacy-and-security/risks/cross-app-scripting#cross-app-scripting-disable-javascript)。

- 静的コンテンツまたは最小限のインタラクティブコンテンツのみを表示する WebView では JavaScript を無効のままにします。該当するものには、静的ヘルプページ、法的文書、リリースノート、その他クライアントサイドスクリプティングを必要としない制御されたコンテンツなどがあります。
- WebView が信頼できるウェブアプリケーションロジックを実行するために意図的に使用される場合にのみ、JavaScript を有効にします。該当するものには、ハイブリッドアプリ画面、複雑な内部ウェブアプリ、シングルページアプリケーション、描画や機能に JavaScript を必要とするウェブベースのユーザーエクスペリエンスなどがあります。

## 実現可能である場合には外部コンテンツに WebView 以外の代替手段を使用する

外部ウェブコンテンツを開くためだけに必要であれば、WebView を埋め込む代わりに [カスタムタブ](https://developer.chrome.com/docs/android/custom-tabs/overview/) の使用を検討します。自身で管理するウェブアプリを配布する場合には、[Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities) も適切なものとなるかもしれません。これらのオプションは描画をアプリの WebView ではなくブラウザのコンテキストに移し、アプリ固有の WebView リスクを軽減できます。ウェブコンテンツ自体を保護する必要性は除かれてはいません。

カスタムタブは認証やその他のブラウザベースのフローに特に適しています。Android はサインインにそれらを推奨しており、ホストアプリがコンテンツを検査できないことを注記しています。また Trusted Web Activities は、ホストアプリがウェブコンテンツや、クッキーや `localStorage` などのウェブ状態に直接アクセスすることも防止します。

## JavaScript が必要とされる場合には WebView を堅牢化する

JavaScript が必要とされる場合には、関連する MASTG ベストプラクティスで説明されている、WebView 固有の堅牢化策を適用して、増加した攻撃対象領域を緩和します。これには以下を含みますが、それに限定されません。

- 想定され、許可リストにあるオリジンのみをロードします。
- `loadUrl`, `shouldOverrideUrlLoading`, または同様の API を呼び出す前に、スキームとホストを検証します。
- 厳密に必要とされる場合を除き、ファイルとコンテンツへのアクセスを無効にします ([WebView でファイルコンテンツを安全にロードする (Securely Load File Content in a WebView)](MASTG-BEST-0011.md) および [WebView でコンテンツプロバイダアクセスを無効にする (Disable Content Provider Access in WebViews)](MASTG-BEST-0013.md))。
- 信頼できないコンテンツへの JavaScript ブリッジの露出を避けます ([従来の JavaScript ブリッジよりもオリジンスコープメッセージングを優先する (Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges)](MASTG-BEST-0035.md))。
- WebView 実装でサポートされている場合にはセーフブラウジングを有効にします。たとえば [`WebSettings.setSafeBrowsingEnabled(true)`](https://developer.android.com/reference/android/webkit/WebSettings#setSafeBrowsingEnabled(boolean)) を呼び出します (Android 8.0, API レベル 26 以降で利用可能)。
