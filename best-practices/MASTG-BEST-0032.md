---
title: UIWebView から WKWebView に移行する (Migrate from UIWebView to WKWebView)
alias: migrate-from-uiwebview-to-wkwebview
id: MASTG-BEST-0032
platform: ios
knowledge: [MASTG-KNOW-0076]
---

Apple は iOS 12 で [`UIWebView`](https://developer.apple.com/documentation/uikit/uiwebview) を非推奨とし、セキュリティとパフォーマンスの向上のために [`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview) を推奨しました。アプリを `WKWebView` に移行して、プロセス外レンダリングや JavaScript 制御の強化など、改善されたセキュリティ機能の恩恵を享受します。`WKWebView` は JavaScript を完全に無効化でき、スクリプトインジェクション脆弱性を防止します。また、ウェブコンテンツとアプリ間の分離を向上し、メインアプリプロセスに影響するメモリ破損のリスクを低減します。さらに、`WKWebView` は Content Security Policy (CSP) などの現代のウェブセキュリティ機能をサポートしており、ウェブコンテンツのセキュリティをさらに強化できます。
