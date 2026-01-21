---
platform: ios
title: クリアテキストトラフィックを許可する App Transport Security 構成 (App Transport Security Configurations Allowing Cleartext Traffic)
id: MASTG-TEST-0322
type: [static]
weakness: MASWE-0050
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0071]
---

## 概要

iOS 9 以降、App Transport Security (ATS) は [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) (通常は `URLSession` 経由) を使用した接続に対して、デフォルトでクリアテキスト HTTP トラフィックをブロックします。但し、アプリは `Info.plist` ファイルの `NSAppTransportSecurity` キーで設定されたいくつかの ATS 例外を通じて、依然としてクリアテキストトラフィックを送信できます。

以下の設定はクリアテキストトラフィックを許可します。

- **`NSAllowsArbitraryLoads`**: `true` に設定すると、`NSExceptionDomains` で指定された個々のドメインを除き、ATS 制限をグローバルに無効にします。これはすべての HTTP 接続を許可します。
- **`NSAllowsArbitraryLoadsInWebContent`**: `true` に設定すると、WebView からのすべての接続に対して ATS 制限を無効にします。
- **`NSAllowsArbitraryLoadsForMedia`**: `true` に設定すると、AV Foundations フレームワークを通じてロードされたメディアに対してすべての ATS 制限を無効にします。
- **`NSExceptionAllowsInsecureHTTPLoads`**: `NSExceptionDomains` での特定のドメインに対して `true` に設定すると、そのドメインへの HTTP 接続を許可します。

ATS 構成の詳細については、[iOS App Transport Security](../../../knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md) を参照してください。

> [!WARNING]
> 制限事項  
> ATS は [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) を介した接続にのみ適用します。[`Network`](https://developer.apple.com/documentation/network) フレームワークや [`CFNetwork`](https://developer.apple.com/documentation/cfnetwork) などの低レベル API は ATS 設定の影響を受けず、その設定に関わらず依然としてクリアテキストトラフィックを許可することがあります。詳細については [クリアテキストトラフィックのための低レベルネットワーク API の使用 (Uses of Low-Level Networking APIs for Cleartext Traffic)](MASTG-TEST-0323.md) を参照してください。

## 手順

1. アプリを抽出します ([アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md))。
2. アプリバンドルから `Info.plist` ファイルを取得します。
3. [ Plist ファイルを JSON に変換する (Convert Plist Files to JSON)](../../../techniques/ios/MASTG-TECH-0138.md) を使用して `Info.plist` を読み取り可能な形式に変換します (必要に応じて)。
4. `NSAppTransportSecurity` ディクショナリでクリアテキストトラフィック例外を調べます。

## 結果

出力には、存在する場合、クリアテキストトラフィックを許可する例外を含む、ATS 構成を含む可能性があります。

## 評価

クリアテキストトラフィックが許可されている場合、そのテストケースは不合格です。これは以下の **いずれか** の条件が満たされた場合に発生する可能性があります。

1. `NSAllowsArbitraryLoads = true` であり、細粒度キー (以下の 2 ～ 4) の **いずれも存在しない場合のみ** (iOS 10 以降ではそれらが `NSAllowsArbitraryLoads` を無視するため)。
2. `NSAllowsArbitraryLoadsInWebContent = true`
3. `NSAllowsArbitraryLoadsForMedia = true`
4. `NSAllowsLocalNetworking = true`
5. `NSExceptionDomains` でのいずれかのドメインが `NSExceptionAllowsInsecureHTTPLoads = true` を設定している。

**コンテキストに関する考慮事項**:

ATS 例外はアプリのコンテキストを考慮して検討する必要があることに注意します。アプリはその本来の目的を果たすために ATS 例外を定義 **しなければならない** ことがあります。たとえば、ブラウザアプリは、HTTP を使用するウェブサイトを含む、任意のウェブサイトに接続する必要があります。そのようなケースでは、適切な [正当な理由を示す文字列](https://developer.apple.com/documentation/security/preventing-insecure-network-connections#Provide-Justification-for-Exceptions) が提供されていれば、例外は許容される可能性があります。但し、Apple は、可能な限りクライアントサイド ATS 例外よりもサーバーサイドの修正を優先することを推奨しています。
