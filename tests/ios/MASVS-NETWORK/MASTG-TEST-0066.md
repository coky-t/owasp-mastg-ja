---
masvs_v1_id:
- MSTG-NETWORK-2
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: TLS 設定のテスト (Testing the TLS Settings)
masvs_v1_levels:
- L1
- L2
---

## 概要

アプリの意図した目的の一部である可能性があることを捨て去るために [対応する正当性を検査する](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) ことを忘れないでください。

特定のエンドポイントとの通信する際に、どの ATS 設定を使用できるかを検証できます。macOS ではコマンドラインユーティリティ `nscurl` を使用できます。指定されたエンドポイントに対してさまざまな設定の並びを実行して検証します。デフォルトの ATS セキュア接続テストに合格していれば、ATS はデフォルトのセキュア設定で使用できます。nscurl の出力に不合格がある場合には、クライアント側の ATS 設定を弱めるのではなく、サーバー側の TLS 設定を変更してサーバー側をよりセキュアにしてください。詳細については [Apple Developer ドキュメント](https://developer.apple.com/documentation/security/preventing_insecure_network_connections/identifying_the_source_of_blocked_connections) の記事 "Identifying the Source of Blocked Connections" を参照してください。

詳細については [ネットワーク通信のテスト](../../../Document/0x04f-Testing-Network-Communication.md#verifying-the-tls-settings) の章の "TLS 設定の検証" セクションを参照してください。
