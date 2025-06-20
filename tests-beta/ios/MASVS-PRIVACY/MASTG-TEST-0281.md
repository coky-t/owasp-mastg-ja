---
platform: ios
title: 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)
id: MASTG-TEST-0281
type: [static, dynamic]
weakness: MASWE-0108
profiles: [P]
---

## 概要

このテストでは、[プライバシーマニフェスト](https://developer.apple.com/documentation/bundleresources/privacy_manifest_files) ファイルの [`NSPrivacyTrackingDomains`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytrackingdomains) セクションで、アプリが通信する可能性のあるすべての既知のトラッキングドメインを適切に宣言しているかどうかを識別します。

このテストを実行するには、既知のトラッカーの厳選されたリストを一つあるいは複数使用します。これらのリストには広告ネットワーク、分析プロバイダ、ユーザープロファイリングサービスに関連するドメインや識別子を含みます。これらは、トラッキング行為を検出してブロックするために、プライバシー重視のツールやブラウザで一般的に使用されます。

リストの例:

- **[DuckDuckGo iOS Trackers](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json)**: ドメイン、マッチングルール、説明、および「アクションピクセル (Action Pixels)」、「広告詐欺 (Ad Fraud)」、「広告誘導トラッキング (Ad Motivated Tracking)」、「広告 (Advertising)」などのカテゴリを含みます。
- **[Exodus Privacy Trackers](https://reports.exodus-privacy.eu.org/en/trackers/)**: トラッカー名、カテゴリ (「広告 (Advertisement)」、「分析 (Analytics)」、「プロファイリング (Profiling)」など)、説明、およびネットワークシグネチャやコードシグネチャなどの検出メタデータを含みます。

これらのリファレンスを使用して、アプリ内のハードコードされたドメインや動的にアクセスされるドメインを照合し、プライバシーマニフェストに適切な宣言が存在するかどうかを検証できます。

## 手順

1. [PrivacyInfo.xcprivacy ファイルの取得 (Retrieving PrivacyInfo.xcprivacy Files)](../../../techniques/ios/MASTG-TECH-0136.md) を使用して、サードパーティ SDK やフレームワークのものを含む、アプリのプライバシーマニフェストファイルを抽出します。
2. [PrivacyInfo.xcprivacy ファイルの解析 (Analyzing PrivacyInfo.xcprivacy Files)](../../../techniques/ios/MASTG-TECH-0137.md) を使用して、プライバシーマニフェストファイルから宣言されたトラッキングドメインのリストを取得します。
3. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) を使用して、静的解析スキャンを実行します。
    - 既知のトラッキングドメインへのハードコードされたリファレンスを検索します。
    - よく知られたトラッキングライブラリへのコードリファレンスを特定します。
4. [mitmproxy](../../../tools/network/MASTG-TOOL-0097.md) でネットワーク解析を実行します。
    - すべての送信ネットワークトラフィックを傍受してログ記録します。
    - 実行時に接触したすべてのドメイン名を抽出します。

## 結果

出力には以下を含む可能性があります。

- アプリから抽出されたすべてのプライバシーマニフェスト。
- マニフェスト内の `NSPrivacyTrackingDomains` キーで宣言されたトラッキングドメインのリスト (関連コンポーネントがあることが望ましい)。
- 動的テスト時に接触したすべてのドメインのリスト。
- 静的解析から得られた、既知のトラッキングドメインまたはトラッキングライブラリのコードマッチのリスト。

## 評価

アプリまたはそのコンポーネント (フレームワーク、プラグインなど) のプライバシーマニフェストファイルの `NSPrivacyTrackingDomains` キーに以下のいずれかが欠けている場合、そのテストは不合格です。

- 実行時にアプリが接触するトラッキングドメイン。
- コード内に見つかったトラッキングドメイン。
- コード内に見つかったトラッキング SDK に対応するドメイン。
