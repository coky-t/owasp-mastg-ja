---
title: WebView 上でのネイティブビューとしてセンシティブ UI を描画する (Render Sensitive UI as Native Views Over the WebView)
alias: render-sensitive-ui-as-native-views-over-webview
id: MASTG-BEST-0059
platform: ios
knowledge: [MASTG-KNOW-0076, MASTG-KNOW-0139]
---

`WKWebView` がクレデンシャル選択、自動入力候補、支払い確認といったセンシティブ UI を提示する必要がある場合、そのインタフェースを WebView 内の HTML 要素としてレンダリングすると、ページ上で実行している JavaScript にさらされます。WebView 内で JavaScript を (たとえば、XSS やコンテンツインジェクションを通じて) 実行できる攻撃者は、それらの要素を読み取り、改変、視覚的に偽装できます。

より安全なアプローチは機密性の高い情報を WebView 上のネイティブ要素として表示することです。ネイティブコンポーネントを使用することで、データは DOM の外部に完全に保持し、JavaScript へのアクセス可能ではなくなります。

## DOM 要素上にネイティブビューをオーバーレイする

アプリは特定の HTML 要素の座標を取得し、この要素の上にネイティブビューを直接表示できます。これは、実際のデータをネイティブ層で保護しつつ、アプリがウェブページのルックアンドフィールを維持することを可能にします。

座標を安全に取得するには、分離された [`WKContentWorld`](https://developer.apple.com/documentation/webkit/wkcontentworld) を使用できます。DOM ジオメトリを読み取るスクリプトを、ページワールドとは別のカスタムワールドに登録することで、そのページの JavaScript がスクリプトを上書きしたり傍受することをできなくします。スクリプト分離にワールドを使用する方法の詳細については [DOM 検査スクリプトには WKContentWorld 分離を使用する (Use WKContentWorld Isolation for DOM Inspection Scripts)](MASTG-BEST-0061.md) を参照してください。
