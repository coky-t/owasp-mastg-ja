---
platform: android
title: WebView を通じて露出するネイティブコード (Native Code Exposed Through WebViews)
id: MASTG-TEST-0334
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013, MASTG-BEST-0035]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0018]
prerequisites:
- identify-security-relevant-contexts
---

## 概要

このテストは、[従来の WebView-Native ブリッジ](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge#addjavascriptinterface) を用いて WebView を使用する Android アプリが、ネイティブコードを WebView 内にロードしたウェブサイトに露出しないことを検証します。

これらのブリッジは [`addJavascriptInterface`](https://developer.android.com/reference/kotlin/android/webkit/WebView#addjavascriptinterface) を通じて WebView に Java オブジェクトを登録することで作成されます。[`@JavascriptInterface`](https://developer.android.com/reference/android/webkit/JavascriptInterface) で注釈付けられたそのオブジェクトのパブリックメソッドは、指定された `name` をグローバル JavaScript オブジェクトとして使用することで、WebView 内で実行している JavaScript から呼び出し可能になります。

このメカニズムが機能するには、[`WebSettings.setJavaScriptEnabled(true)`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean)) (デフォルトは `false`) を呼び出すことで、WebView 上での JavaScript の実行を有効にする必要があります。露出したインタフェースはそのページ内で実行される JavaScript コードから呼び出されるためです。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) ツールを実行して、関連する WebView API への参照を探します。

## 結果

出力には関連する WebView API への参照を含む可能性があります。

## 評価

以下をすべて満たす場合、そのテストケースは不合格です。

- `setJavaScriptEnabled` は明示的に `true` に設定されている。
- `addJavascriptInterface` は少なくとも一度使用されている。
- `@JavascriptInterface` で注釈付けられたメソッドのうち少なくとも一つが機密データまたはアクションを扱い、信頼できないコンテンツに到達可能である。下記参照。

**状況に関する考慮事項**:

誤検出を減らすため、関連するコードが安全でないと報告する前に、ブリッジが使用されているコンテキストを必ず理解します。機密データやアクションを保護するためのセキュリティ関連コンテキストで使用されていること、および信頼できないコンテンツから到達可能であることを確認します。たとえば、WebView が任意の URL や十分に検証されていない URL をロードできる場合、またはアプリがブリッジに対して適切なオリジン許可リストを実装していない場合です。

**WebView-Native ブリッジのテストにおけるよく知られた課題**:

- アプリは、たとえばユーティリティメソッドやラッパークラスを通じて、これらの API へのパラメータ化や間接呼び出しを使用することがあります。静的解析ではこれらの呼び出しを解決できない可能性があり、動的解析では特定のアプリ状態やユーザーインタラクションでトリガーする必要があるかもしれません。
- アプリは異なる設定を持つ複数の WebView を使用する可能性があり、特にそれらが動的に、異なるコードパスで、または異なるファイル間で作成される場合には、各 WebView インスタンスにどの値が設定されているかを判断することが難しいことがあります。
- アプリは、これらの API の使用を隠すために、難読化、リフレクション、または動的コードローディングを使用することがあります。
