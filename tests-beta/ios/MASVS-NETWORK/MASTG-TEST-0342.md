---
platform: ios
title: Info.plist 内の脆弱な ATS TLS ポリシー例外への参照 (References to Weak ATS TLS Policy Exceptions in Info.plist)
id: MASTG-TEST-0342
type: [static]
weakness: MASWE-0050
profiles: [L1, L2]
best-practices: [MASTG-BEST-0042]
knowledge: [MASTG-KNOW-0071]
---

## 概要

アプリは `Info.plist` 内の `NSAppTransportSecurity` 例外を通じて ATS の TLS 強制を弱めることができます。具体的には以下があります。

- [`NSExceptionMinimumTLSVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionminimumtlsversion) は、非推奨の TLS 1.0 および TLS 1.1 を含む、TLS バージョン 1.2 未満のサーバーへの接続を許可します。
- [`NSExceptionRequiresForwardSecrecy`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionrequiresforwardsecrecy) を `false` を設定すると、[Perfect Forward Secrecy (PFS)](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) の ATS 要件を無効になり、TLS 自体が必須の場合でも、接続の機密性を弱めます。

これらの例外は `NSExceptionDomains` の下にあるドメインごとに適用されます。スコープが広い場合 (特に `NSIncludesSubdomains = true` の場合)、多くのホストに影響を及ぼし、[中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃の攻撃対象領域を拡大する可能性があります。Apple は App Store に申請する際に、これらの例外の正当化理由を求めています。ATS 構成と例外の詳細については [iOS App Transport Security](../../../knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md) を参照してください。

アプリは [`NSAllowsArbitraryLoads`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsallowsarbitraryloads) を `true` に設定することで、ATS をグローバルに無効にすることもできます。これは、最小 TLS バージョンや前方秘匿性などの ATS 要件を含む、URL ローディングシステムを通じて行われる接続に対する ATS 保護を無効にし、プレーンテキスト HTTP 通信を許可します。また ATS 固有の証明書要件を緩和することもあります。URL ローディングシステムによって実行されるベースライン TLS/X.509 証明書チェーンのバリデーションとサーバー信頼性評価は依然として適用します。`NSExceptionDomains` の下にあるドメインごとのエントリはグローバル設定を上書きします。たとえば、`NSAllowsArbitraryLoads` が `true` であっても `tls-v1-2.example.com` が `NSExceptionMinimumTLSVersion = "TLSv1.2"` を持つ場合、そのドメインは依然として TLS 1.2 以上を要求します。一方、他のすべてのドメインは ATS が無効になっています。これは他のすべてのドメインがプレーンテキスト HTTP を使用する機能を含みます。

## 手順

1. アプリを抽出します ([アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md))。
2. アプリバンドル内の `Info.plist` を探します。
3. 必要に応じて [Plist ファイルを JSON に変換する (Convert Plist Files to JSON)](../../../techniques/ios/MASTG-TECH-0138.md) を使用して `Info.plist` を読み取り可能な形式に変換します。
4. TLS ポリシー例外、特に `NSExceptionMinimumTLSVersion`, `NSExceptionRequiresForwardSecrecy`, `NSAllowsArbitraryLoads` について、`NSAppTransportSecurity` ディクショナリを調べます。

## 結果

出力には `NSAppTransportSecurity` で設定されている TLS ポリシー例外を含む可能性があります (存在する場合)。

## 評価

以下の条件の **いずれ** が満たされる場合、そのテストケースは不合格です。

1. `NSAllowsArbitraryLoads` を `true` に設定している。これは `NSExceptionDomains` にリストされていないドメインへのすべての接続に対して ATS を無効にします。`NSExceptionDomains` のドメインごとの例外は依然としてそれぞれのドメインごとに適用しますが、他のすべてのドメインには ATS の制限はありません。
2. いずれかのドメイン、IP アドレス、IP アドレス範囲で `NSExceptionMinimumTLSVersion` を `TLSv1.0` または `TLSv1.1` に設定している。
3. いずれかのドメイン、IP アドレス、IP アドレス範囲で `NSExceptionRequiresForwardSecrecy` を `false`, `NO`, または `0` に設定している。

> [!NOTE]
> "App Store 申請コンテキスト"  
> Apple は App Store 申請時の ATS 例外について [正当化理由](https://developer.apple.com/documentation/security/preventing-insecure-network-connections#Provide-Justification-for-Exceptions) を要求することがあります。可能であれば、その証跡をコンテキスト情報としてのみレポートに記録します。
