---
title: ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)
platform: network
id: MASTG-TEST-0236
type: [dynamic]
weakness: MASWE-0050
profiles: [L1, L2]
---

## 概要

このテストはアプリの送受信ネットワークトラフィックを傍受して、クリアテキスト通信をチェックします。
静的チェックでは _潜在的な_ クリアテキストトラフィックを示すだけですが、この動的テストではアプリケーションが確かに行うすべての通信を示します。

!!! 警告 制限事項
    - ネットワークレベルでトラフィックを傍受すると、単一のアプリだけでなく、_デバイス_ が実行するすべてのトラフィックを示します。トラフィックを特定のアプリにリンクさせることは、特にデバイスに複数のアプリがインストールされている場合、困難です。
    - 傍受したトラフィックをアプリの特定の場所にリンクすることは困難であり、コードを手作業で解析する必要があります。
    - 動的解析はアプリを広範囲に操作する場合に最適です。しかし、その場合でも、すべてのデバイスで実行することが困難であったり不可能であるコーナーケースが存在する可能性があります。したがって、このテストの結果は包括的ではないかもしれません。

## 手順

以下のいずれかのアプローチを使用できます。

- すべてのトラフィックをキャプチャするには [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/android/MASTG-TECH-0010.md) (Android の場合) または [基本的なネットワークモニタリング/スニッフィング (Basic Network Monitoring/Sniffing)](../../../techniques/ios/MASTG-TECH-0062.md) (iOS の場合) をセットアップします。
- すべてのトラフィックをキャプチャするには [傍受プロキシの設定 (Setting Up an Interception Proxy)](../../../techniques/android/MASTG-TECH-0011.md) (Android の場合) または [傍受プロキシの設定 (Setting Up an Interception Proxy)](../../../techniques/ios/MASTG-TECH-0063.md) (iOS の場合) をセットアップします。

**注**:

- 傍受プロキシは HTTP(S) トラフィックのみを示します。ただし、[Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) などのツール固有のプラグインや [MITM Relay](../../../tools/network/MASTG-TOOL-0078.md) などの他のツールを使用して、XMPP やその他のプロトコルを介した通信をデコードして可視化できます。
- 一部のアプリでは、証明書のピン留めのため、Burp や [ZAP](../../../tools/network/MASTG-TOOL-0079.md) などのプロキシが正しく機能しないことがあります。そのようなシナリオでも、基本的なネットワークスニフィングを使用してクリアテキストトラフィックを検出できます。さもなければ、ピン留めを無効にしてみてください (Android の場合 [証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../../../techniques/android/MASTG-TECH-0012.md)、iOS の場合 [証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../../../techniques/ios/MASTG-TECH-0064.md) を参照してください)。

## 結果

出力にはキャプチャしたネットワークトラフィックを含みます。

## 評価

クリアテキストトラフィックがターゲットアプリから発生する場合、そのテストケースは不合格です。

**注**: トラフィックはデバイス上のどのアプリからも発生する可能性があるため、これを判断することは困難となる可能性があります。[概要](#overview) セクションを参照してください。
