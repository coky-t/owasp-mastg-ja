---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: 機密データがサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0206, MASTG-TEST-0281]
deprecation_note: New version available in MASTG V2
---

## 概要

機密情報はいくつかの手段でサードパーティに漏れる可能性があります。iOS では一般的にアプリに埋め込まれたサードパーティサービスを経由します。

これらのサービスが提供する機能には、アプリ使用時のユーザーの行動を監視する追跡サービス、バナー広告の販売、ユーザーエクスペリエンスの向上などがあります。

好ましくない点としては、開発者は通常、サードパーティライブラリを介して実行されるコードの詳細を知らないことです。したがって、必要以上の情報をサービスに送信すべきではなく、機密情報を開示すべきではありません。

ほとんどサードパーティサービスは以下の二つの方法で実装されています。

- スタンドアロンライブラリで実装
- フル SDK で実装

## 静的解析

サードパーティライブラリによって提供される API コールや関数がベストプラクティスに従って使用されているかどうかを判断するには、ソースコードとリクエストされるパーミッションをレビューし、既知の脆弱性がないかチェックします。

サードパーティのサービスに送信されるすべてのデータは、サードパーティがユーザーアカウントを特定できるような PII (個人を識別できる情報) の露出を防ぐために匿名化されるべきです。その他のデータ (ユーザーアカウントやセッションにマップできる ID など) はサードパーティに送信すべきではありません。

## 動的解析

機密情報が埋め込まれていないか、外部サービスへのすべてのリクエストをチェックします。
クライアントとサーバー間のトラフィックを傍受するには、たとえば [Burp Suite](../../../tools/network/MASTG-TOOL-0077.md) や [ZAP](../../../tools/network/MASTG-TOOL-0079.md) を使用して、[中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃 ([基本的なネットワークモニタリングとスニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/ios/MASTG-TECH-0062.md)) を行うことで動的解析を実施できます。トラフィックを傍受プロキシ経由とすることで、アプリとサーバー間を通過するトラフィックを盗聴してみることができます。メイン機能がホストされているサーバーに直接送信されないすべてのアプリリクエストは、トラッカーや広告サービスの PII などの機密情報がないかチェックする必要があります。
