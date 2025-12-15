---
title: ネットワークトラフィックでの証明書ピン留めの欠如 (Missing Certificate Pinning in Network Traffic)
platform: network
id: MASTG-TEST-0244
type: [network]
weakness: MASWE-0047
profiles: [L2]
knowledge: [MASTG-KNOW-0015]
---

## 概要

Android Network Security Config、カスタム TrustManager 実装、サードパーティライブラリ、ネイティブコードなど、アプリケーションが証明書のピン留めを実装する複数の方法があります。一部の実装には、特に難読化や動的コードローディングが関与する場合、静的解析では特定が困難なものがあるため、このテストではネットワーク傍受技法を使用して、実行時に証明書のピン留めが強制されているかどうかを判断します。

このテストの目的は [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) がアプリから HTTPS トラフィックを傍受できるかどうかを観察することです。MITM 傍受に成功した場合、アプリが証明書のピン留めを使用していないか、正しく実装していないことを示しています。

アプリが証明書ピン留めを適切に実装している場合、CA がシステムによって信頼されている場合でも、アプリは認可されていない CA によって発行された証明書を拒否するため、MITM 攻撃は失敗するはずです。

_テストのヒント:_ MITM 攻撃を実行する際、システムログを監視すると便利です ([システムログの監視 (Monitoring System Logs)](../../../techniques/android/MASTG-TECH-0009.md) を参照)。証明書のピン留め/バリデーションチェックが失敗した場合、以下のログエントリのようなイベントが表示されるかもしれません。これはアプリが MITM 攻撃を検出して接続を確立しなかったことを示します。

`I/X509Util: Failed to validate the certificate chain, error: Pin verification failed`

## 手順

1. 傍受プロキシを設定します。[傍受プロキシの設定 (Setting Up an Interception Proxy)](../../../techniques/android/MASTG-TECH-0011.md) を参照してください。
2. そのプロキシに接続されたデバイスにアプリケーションをインストールし、通信を傍受します。
3. 傍受したすべてのドメインを抽出します。

## 結果

出力には傍受が成功したドメインのリストを含む可能性があります。

## 評価

関連するドメインのいずれかが傍受された場合、そのテストケースは不合格です。
