---
platform: ios
title: 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)
id: MASTG-TEST-0281
type:
  - static
  - dynamic
weakness: MASWE-0108
profiles:
  - P
---

# MASTG-TEST-0281 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)

### 概要

このテストでは、[プライバシーマニフェスト](https://developer.apple.com/documentation/bundleresources/privacy_manifest_files) ファイルの [`NSPrivacyTrackingDomains`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytrackingdomains) セクションで、アプリが通信する可能性のあるすべての既知のトラッキングドメインを適切に宣言しているかどうかを識別します。

このテストを実行するには、既知のトラッカーの厳選されたリストを一つあるいは複数使用します。これらのリストには広告ネットワーク、分析プロバイダ、ユーザープロファイリングサービスに関連するドメインや識別子を含みます。これらは、トラッキング行為を検出してブロックするために、プライバシー重視のツールやブラウザで一般的に使用されます。

リストの例:

* [**DuckDuckGo iOS Trackers**](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json): ドメイン、マッチングルール、説明、および「アクションピクセル (Action Pixels)」、「広告詐欺 (Ad Fraud)」、「広告誘導トラッキング (Ad Motivated Tracking)」、「広告 (Advertising)」などのカテゴリを含みます。
* [**Exodus Privacy Trackers**](https://reports.exodus-privacy.eu.org/en/trackers/): トラッカー名、カテゴリ (「広告 (Advertisement)」、「分析 (Analytics)」、「プロファイリング (Profiling)」など)、説明、およびネットワークシグネチャやコードシグネチャなどの検出メタデータを含みます。

これらのリファレンスを使用して、アプリ内のハードコードされたドメインや動的にアクセスされるドメインを照合し、プライバシーマニフェストに適切な宣言が存在するかどうかを検証できます。

API に関して、アプリが外部サーバーと通信できるようにする、`URLSession`, `NSURLSession`, `NSURLConnection` などのネットワーク API や、サードパーティのネットワークライブラリ (Alamofire, AFNetworking など) を検討する必要があります。さらに、トラッキング機能の存在を示す可能性のある、よく知られたトラッキングライブラリ (Facebook SDK, Google Analytics など) への参照を探します。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。
3. [文字列の取得 (Retrieving Strings)](../../../techniques/generic/MASTG-TECH-0071.md) を使用して、既知のトラッキングドメインを表すハードコードされた文字列を検索します。
4. [PrivacyInfo.xcprivacy ファイルの取得 (Retrieving PrivacyInfo.xcprivacy Files)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0136.md) を使用して、サードパーティ SDK やフレームワークのものを含め、アプリのプライバシーマニフェストファイルを抽出します。
5. [PrivacyInfo.xcprivacy ファイルの解析 (Analyzing PrivacyInfo.xcprivacy Files)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0137.md) を使用して、プライバシーマニフェストファイルから宣言されたトラッキングドメインのリストを取得します。
6. [基本的なネットワークモニタリングとスニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/ios/MASTG-TECH-0062.md) を使用して、すべての送信ネットワークトラフィックを傍受してログ記録します。

### 結果

出力には以下を含む可能性があります。

* アプリから抽出されたすべてのプライバシーマニフェスト。
* マニフェスト内の `NSPrivacyTrackingDomains` キーで宣言されたトラッキングドメインのリスト (関連コンポーネントがあることが望ましい)。
* 実行時に接触したすべてのドメインを抽出できる、ネットワークトラフィックのキャプチャ。
* 動的テスト時に接触したすべてのドメインのリスト。
* 静的解析から得られた、既知のトラッキングドメインまたはトラッキングライブラリのコードマッチのリスト。

### 評価

アプリまたはそのコンポーネント (フレームワーク、プラグインなど) のプライバシーマニフェストファイルの `NSPrivacyTrackingDomains` キーに以下のいずれかが欠けている場合、そのテストケースは不合格です。

* 実行時にアプリが接触するトラッキングドメイン。
* コード内に見つかったトラッキングドメイン。
* コード内に見つかったトラッキング SDK に対応するドメイン。
