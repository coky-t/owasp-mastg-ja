---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: 機密データが組み込みサービスを介してサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0318, MASTG-TEST-0319]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

サードパーティライブラリが提供する API コールや関数がベストプラクティスに従って使用されているかどうかを判断するには、そのソースコード、要求されるパーミッションをレビューし、既知の脆弱性がないかチェックします。

サードパーティサービスに送信されるすべてのデータは、サードパーティがユーザーアカウントを特定できるような PII (個人を識別できる情報) の漏洩を防ぐために匿名化する必要があります。その他のデータ (ユーザーアカウントやセッションにマップできる ID など) はサードパーティに送信すべきではありません。

## 動的解析

外部サービスへのすべてのリクエストに機密情報が埋め込まれていないかチェックします。
クライアントとサーバー間のトラフィックを傍受するには、[Burp Suite](../../../tools/network/MASTG-TOOL-0077.md) や [ZAP](../../../tools/network/MASTG-TOOL-0079.md) を使用して [中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃を行うことで、動的解析を実施できます。トラフィックを傍受プロキシ経由とすることで、アプリとサーバー間を通過するトラフィックを盗聴してみることができます。メイン機能がホストされているサーバーに直接送信されないすべてのアプリリクエストは、トラッカーや広告サービスの PII などの機密情報がないかチェックする必要があります。
