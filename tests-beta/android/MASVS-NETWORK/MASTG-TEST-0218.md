---
title: ネットワークトラフィックにおける安全でない TLS プロトコル (Insecure TLS Protocols in Network Traffic)
platform: network
id: MASTG-TEST-0218
type: [network]
weakness: MASWE-0050
---

## 概要

静的解析は安全でない TLS バージョンを許可する構成を識別できますが、ライブ通信で使用される実際のプロトコルを正確に反映していない可能性があります。これは、実行時にクライアント (アプリ) とサーバーの間で TLS のバージョンネゴシエーションが行われ、最も安全で相互にサポートしているバージョンに合意するためです。

実際のネットワークトラフィックをキャプチャして解析することで、実際にネゴシエートして使用している TLS バージョンを観察できます。このアプローチでは、特定の TLS バージョンを強制したり制限するサーバーの構成を考慮した、プロトコルのセキュリティの正確なビューを提供します。

静的解析が不完全または実行不可能な場合には、ネットワークトラフィックを調べることで、安全でない TLS バージョン (TLS 1.0 や TLS 1.1 など) がアクティブに使用されているインスタンスを明らかにできます。

## 手順

1. [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/android/MASTG-TECH-0010.md) (Android の場合) または [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/ios/MASTG-TECH-0062.md) (iOS の場合) をセットアップします。
2. [Wireshark](../../../tools/network/MASTG-TOOL-0081.md) などを使用して TLS バージョンを確認します。

## 結果

出力には実際に使用されている TLS バージョンを表示します。

## 評価

[安全でない TLS バージョン](../../../Document/0x04f-Testing-Network-Communication.md#recommended-tls-settings) が使用されている場合、テストケースは不合格です。
