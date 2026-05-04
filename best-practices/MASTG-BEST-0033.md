---
title: WebView にファイルコンテンツを安全にロードする (Securely Load File Content in a WebView)
alias: securely-load-file-content-in-webview-ios
id: MASTG-BEST-0033
platform: ios
knowledge: [MASTG-KNOW-0076]
---

## `allowFileAccessFromFileURLs` と `allowUniversalAccessFromFileURLs` の有効化を避ける

`WKWebView` については、`allowFileAccessFromFileURLs` と `allowUniversalAccessFromFileURLs` は iOS の公開 `WKWebView` API にはありません。これらは通常 Key-Value Coding (KVC) を通じてアクセスされますが、特別で正当な理由がない限り無効にしておくべきです。

これらのプロパティを有効にしなければならない場合、以下を確認します。

- WebView は管理されたソースから信頼できるコンテンツのみをロードしていること。
- 適切な入力バリデーションとサニタイゼーションが実装されていること。
- アプリは WebView へのアクセス可能な場所に機密データを保存していないこと。

これらの設定は `WKWebView` にのみ適用します。`UIWebView` は歴史的にはより広範なローカルファイルアクセスを許可し、`WKWebView` により提供される最新の分離と制御モデルを欠落していました。これは `UIWebView` が非推奨であり置き換えられた理由の一つです。[UIWebView から WKWebView に移行する (Migrate from UIWebView to WKWebView)](MASTG-BEST-0032.md) を参照してください。

## ローカルファイルを安全にロードする

[`loadHTMLString(_:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadhtmlstring(_:baseurl:)/) または [`load(_:mimeType:characterEncodingName:baseURL:)`](https://developer.apple.com/documentation/webkit/wkwebview/load(_:mimetype:characterencodingname:baseurl:)) を使用してローカル HTML をロードする場合には、`baseURL` を意図的に設定します。

- `WKWebView` については、`baseURL` に `nil` を設定すると、ドキュメントのオリジンを不透明にします。これはローカルファイルと同じオリジンとして扱われることを防ぎ、他のローカルリソースへのアクセスを抑制するのに役立ちます。
- ページが CSS、画像、JavaScript などのバンドルされたサブリソースを必要とする場合は、読み取りアクセス URL を限定した [`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:)) または [`loadFileRequest(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfilerequest(_:allowingreadaccessto:)) をお勧めします。
- `file://` ベース URL を使用する場合は、アプリバンドルなどの管理されたリソースの場所に限定します。

厳密に必要な場合を除き、広範な `file://` ベース URL を避けます。

## `loadFileURL` と `loadFileRequest` を注意深く使用する

[`loadFileURL(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:)) または [`loadFileRequest(_:allowingReadAccessTo:)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfilerequest(_:allowingreadaccessto:)) を使用する場合は、`allowingReadAccessTo` パラメータが **必要最低限のファイルシステムスコープ** を付与していることを確認します。

```swift
// Good: Restrict access to a specific file
let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("safe.html")

webView.loadFileURL(fileURL, allowingReadAccessTo: fileURL)
```

```swift
// Risky: Grants access to an entire directory
let dirURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

webView.loadFileURL(fileURL, allowingReadAccessTo: dirURL) // Avoid if possible
```

ディレクトリアクセスが必要とされる場合は、ディレクトリは WebView アセットのみを含み、機密性の高いアプリデータを含まないようにします。

## その他の考慮事項

これらの予防措置を講じた場合でも、WebView は信頼できるソースからのコンテンツのみをロードすべきです。攻撃者が制御する JavaScript がローカルファイルを読み取ることができる WebView で実行すると、アプリのサンドボックスから機密データを読み取って流出する可能性があります。

- WebView が静的コンテンツのみを表示する場合には、[`WKWebpagePreferences.allowsContentJavaScript = false`](https://developer.apple.com/documentation/webkit/wkwebpagepreferences/allowscontentjavascript) を使用して、コンテンツの JavaScript を無効にします。
- HTML や JavaScript のインジェクションを防ぐために、信頼できない入力を WebView にロードしないようにします。
- WebView がアクセス可能なファイルはアプリのデータ、シークレット、コンフィデンシャルとは分けるようにします。
- 幅広い `file://` パスではなく、アプリバンドルまたは管理されたソースからコンテンツをロードすることを推奨します。
- アプリが管理するドメインのみにアクセスし、強力な WebKit API を使用する WebView には [App Bound Domains](https://webkit.org/blog/10882/app-bound-domains/) を検討します。
