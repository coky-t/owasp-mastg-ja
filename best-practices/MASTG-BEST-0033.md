---
title: WebView にファイルコンテンツを安全にロードする (Securely Load File Content in a WebView)
alias: securely-load-file-content-in-webview-ios
id: MASTG-BEST-0033
platform: ios
knowledge: [MASTG-KNOW-0076]
---

アプリがアプリストレージから HTML/JavaScript をロードする静的ウェブコンポーネントに依存している場合、悪意のあるペイロードがそのストレージ内の他のファイルにアクセスできないようにします。アプリは [`loadFileURL(_ URL: URL, allowingReadAccessTo readAccessURL: URL)`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:)) を使用して WebKit コンテンツをサンドボックス化し、ウェブサイトが特定のディレクトリ内のファイルのみにアクセスできるようにします。

ファイルアクセスを制限することで、`<img src="../secret.jpg">` や `<frame src="../secret.txt">` などの悪意のあるインジェクションペイロードが、ファイルシステム内の他のディレクトリから機密データを抽出することを防ぎます。

この制限を適用するには、アプリは静的ウェブコンテンツ専用のディレクトリを使用する必要があります。

1. 静的ウェブサイトがアプリバンドル内に存在する場合、`readAccessURL` にウェブサイトリソースのみを含むディレクトリを設定します。
2. 静的ウェブサイトがアプリストレージ内に存在する場合、`Library/Application Support` ディレクトリ内に専用のディレクトリを作成します。

例:

```txt
<CONTAINER>/
   Documents/
   tmp/
   Library/
      Application Support/
         sandbox-for-website/
            index.html
```
