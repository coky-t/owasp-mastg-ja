---
title: GlobalWebInspect
platform: ios
source: https://github.com/ChiChou/GlobalWebInspect
hosts: [ios]
---

> [!WARNING]
> 
> このツールは macOS / iOS の組み合わせによっては動作する場合としない場合があります。

GlobalWebInspect は脱獄済み iOS デバイス にインストールすることで、通常は公開していないアプリ内の `WKWebView` および JavaScriptCore ウェブコンテンツに Safari Web Inspector をアタッチできます。パッケージをデバイスにコピーして `sudo dpkg -i <file>.deb` を実行するか、脱獄パッケージマネージャを通じてインストールすることにより、この Tweak をインストールできます。[ElleKit](MASTG-TOOL-0139.md) などの、MobileSubstrate 互換のフック環境が必要です。

## 動作原理

iOS 16.4 以降では、GlobalWebInspect は `WKWebView` の作成および `JSContext` 関連オブジェクトをフックし、強制的に検査を有効にします。プロジェクト自体のコードと README には、`WKWebView` の作成と `JSContext` をフックすると記載しており、その実装では `-[WKWebView _initializeWithConfiguration:]` の中で `WKWebView` の `setInspectable:` を呼び出し、JavaScriptCore コンテキストに対して `JSGlobalContextSetInspectable(..., true)` を呼び出すことを示しています。

それ以前の iOS バージョンでは、そのメカニズムは異なります。README によると、`webinspectord` はプロセスを検査可能なものとしてリストする前に、`com.apple.security.get-task-allow` や Web Inspector 関連の複数のエンタイトルメントなど、特定のエンタイトルメントをチェックします。GlobalWebInspect は `webinspectord` に注入し、これらのエンタイトルメントクエリに対して `true` を返すため、通常は拒否されるアプリでも Safari Web Inspector に現れます。
