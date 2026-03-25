---
title: WebView の入力を検証する (Validate WebView Input)
alias: validate-webview-input
id: MASTG-BEST-0034
platform: ios
knowledge: [MASTG-KNOW-0076]
---

アプリによって完全に制御されている場合を除き、[`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) に渡されるデータを常に信頼できないものとして扱います。これは、[`load(_:)`](https://developer.apple.com/documentation/webkit/wkwebview/load(_:)) を通じてロードされる URL、[`loadFileURL`](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl(_:allowingreadaccessto:)) を通じてロードされるローカルファイル、[`loadHTMLString`](https://developer.apple.com/documentation/webkit/wkwebview/loadhtmlstring(_:baseurl:)) に渡される HTML、[`evaluateJavaScript`](https://developer.apple.com/documentation/webkit/wkwebview/evaluatejavascript(_:completionhandler:)) に渡される JavaScript、および描画ページに挿入される任意のデータを含みます。

アプリが `WKWebView` に URL をロードする場合、その URL はパースされ、想定されるスキーム、ホスト、パス、その他の関連コンポーネントの厳格な許可リストに対して検証される必要があります。ディープリンク、カスタム URL スキーム、ペーストされたテキスト、サーバーが提供する値など、攻撃者が制御できる入力が、任意の WebView の宛先を決定することを許可してはいけません。

ディープリンクおよびカスタム URL スキームでは、既知のコマンドと固定の宛先のみを受け入れます。任意の URL パラメータを `WKWebView.load(_:)` に直接渡してはいけません。

信頼できないデータをウェブコンテンツ内に表示する必要がある場合、[`innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) や文字列を構築した `evaluateJavaScript` 呼び出しなどの HTML および JavaScript インジェクションパターンを避けます。安全なテキストのみのレンダリングとコンテキストに応じたエスケープ処理を優先します。

ローカルコンテンツを `loadFileURL` でロードする場合、`allowingReadAccessTo` を可能な限り狭く保ち、広範囲なローカルファイルアクセスと信頼できない HTML やスクリプトのインジェクションを決して組み合わせてはいけません。
