---
title: 従来の JavaScript ブリッジよりもオリジンスコープメッセージングを優先する (Prefer Origin Scoped Messaging Over Legacy JavaScript Bridges)
alias: prefer-origin-scoped-messaging-over-legacy-javascript-bridges
id: MASTG-BEST-0035
platform: android
knowledge: [MASTG-KNOW-0018]
---

JavaScript ブリッジは本質的に安全でないわけではありませんが、影響の大きい `WebView` 機能であり、完全に信頼できるコンテンツにのみ公開すべきです。主なリスクはブリッジ単体ではなく、ブリッジと信頼できないコンテンツまたは検証が不十分なコンテンツとの組み合わせにあります。

## 従来の `addJavascriptInterface` モデルを避ける

[従来の `addJavascriptInterface`](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge#addjavascriptinterface) メカニズムは、iframe を含む `WebView` 内のすべてのフレームに公開されており、オリジンベースのアクセス制御を提供していません。そのため、`WebView` が信頼できないコンテンツや検証が不十分なコンテンツを描画する場合、セキュリティ境界として不適切になります。

Android では [`addJavascriptInterface()` を使用するためのより安全な方法の一つ](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges#addjavascriptinterface-risks-target-api-level-21-or-higher) は [API レベル 21 以降をターゲットにする](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)) ことであるとも言及しています。JavaScript は `@JavascriptInterface` で明示的に注釈付けされたメソッドにのみアクセスできるのに対し、古いターゲットレベルでは注入されたオブジェクトのパブリックフィールドも公開されているためです。その改善があっても、このメカニズムにはオリジンベースのアクセス制御が依然として欠けているため、Android は最新のブリッジ設計にはオリジン認識の代替手段を推奨しています。

## ブリッジが必要な場合には `addWebMessageListener` を優先する

Android は **推奨** の最新ブリッジメカニズムとして [`addWebMessageListener`](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge) を明示的にドキュメント化しています。これは最も最新かつ推奨されるアプローチとして説明されており、[メカニズム比較表](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge#summary-mechanisms) では **推奨: はい** および **セキュリティ: 最上位 (評価リストに基づく)** としてマークされています。

ウェブコンテンツとネイティブコード間の通信が必要で、信頼できるオリジンの限定的な許可リストを定義できる場合に使用します。厳格な `allowedOriginRules` セットを構成し、`loadUrl()` を呼び出す前にリスナーを登録し、メッセージ処理前にコールバックで送信者情報を検証します。

## `postWebMessage` は代替手段としてのみ使用する

Android は **代替** 非同期メッセージングメカニズムとして [`postWebMessage`](https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge) をドキュメント化しています。同じ比較表で **推奨: いいえ** および **セキュリティ: 高 (オリジン認識)** としてマークされており、`addJavascriptInterface` よりは強力ですが `addWebMessageListener` ほど強力ではありません。

このメカニズムを使用する場合、厳密にターゲットオリジンを構成し、`*` などのワイルドカードターゲットを避けます。Android のセキュリティガイダンスでは、`postWebMessage()` と `postMessage()` のオリジン制御の欠如は、攻撃者がメッセージを傍受したり、ネイティブハンドラにメッセージを送信することを許してしまう可能性があると具体的に警告しています。

## ネイティブ機能の公開を最小限に抑える

ブリッジメカニズムに関わらず、JavaScript に公開するネイティブ機能を最小限に抑えます。

- ページが必要とする特定の操作のみを公開する
- 幅広いユーティリティオブジェクトや汎用のコマンドディスパッチャを避ける
- 必要不可欠な場合を除き、機密性の高い機能を公開しない
- シンプルで明確に定義されたメッセージ形式を要求する
- 予期しない入力やサポートされていない操作を拒否する

## スコープと制限

このベストプラクティスはブリッジ設計とオリジンスコープに関するものです。JavaScript の有効化、信頼できるオリジンの制限、ファイルアクセスの堅牢化といった関連するコントロールと組み合わせる必要があります。これ自体だけでは攻撃者が制御する JavaScript が信頼できるページで実行することを防ぐことはできません。
