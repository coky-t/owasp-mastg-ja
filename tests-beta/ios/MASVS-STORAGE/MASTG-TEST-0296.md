---
platform: ios
title: 安全でないログ記録による機密データ露出 (Sensitive Data Exposure Through Insecure Logging)
id: MASTG-TEST-0296
type: [dynamic]
weakness: MASWE-0001
prerequisites:
- identify-sensitive-data
best-practices: [MASTG-BEST-0022]
profiles: [L1, L2]
---

## 概要

このテストは [ログへの機密データの挿入 (Insertion of Sensitive Data into Logs)](MASTG-TEST-0297.md) と対をなす動的テストです。

このテストでは、デバイスログを監視およびキャプチャして、機密データについて解析します。

### !!! 警告 制限事項
- ログをアプリの特定の場所にリンクするのは困難なことがあり、コードを手動で解析する必要があります。代替手段として [Frida for iOS](../../../tools/ios/MASTG-TOOL-0039.md) で動的解析を使用できます。
- 動的解析は、アプリと広範囲にやり取りする場合に最も機能します。しかし、それでもすべてのデバイスで実行するのが困難または不可能なコーナーケースがある可能性があります。そのため、このテストの結果は網羅的ではない可能性があります。

## 手順

1. デバイスにアプリをインストールします ([アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md)).
2. [システムログの監視 (Monitoring System Logs)](../../../techniques/ios/MASTG-TECH-0060.md) でログを監視します。
3. アプリを開きます。
4. ログ出力を解析したいモバイルアプリに移動します。
5. アプリを閉じます。

## 結果

出力にはすべてのログ記録されたデータを含む可能性があります。

## 評価

出力内に機密データを見つけた場合、そのテストケースは不合格です。
