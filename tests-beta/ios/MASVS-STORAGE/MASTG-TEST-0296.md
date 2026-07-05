---
platform: ios
title: ログ内の機密データ露出 (Sensitive Data Exposure in Logs)
id: MASTG-TEST-0296
type:
  - dynamic
  - logs
weakness: MASWE-0001
prerequisites:
  - identify-sensitive-data
best-practices:
  - MASTG-BEST-0022
profiles:
  - L1
  - L2
knowledge:
  - MASTG-KNOW-0101
---

# MASTG-TEST-0296 ログ内の機密データ露出 (Sensitive Data Exposure in Logs)

### 概要

このテストは [ログ記録 API を通じた機密データ露出 (Sensitive Data Exposure Through Logging APIs)](MASTG-TEST-0297.md) と対をなす動的テストです。

このテストでは、デバイスログが監視され、キャプチャされ、機密データについて解析されます。

> \[!WARNING] 制限事項
>
> * ログをアプリの特定の場所にリンクするのは困難なことがあり、コードを手動で解析する必要があります。代替手段として [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0095.md) を使用できます。
> * 動的解析は、アプリと広範囲にやり取りする場合に最も機能します。しかし、それでもすべてのデバイスで実行するのが困難または不可能なコーナーケースがある可能性があります。そのため、このテストの結果は網羅的ではない可能性があります。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [システムログの監視 (Monitoring System Logs)](../../../techniques/ios/MASTG-TECH-0060.md) を使用して、デバイスログを監視します。
3. アプリを開きます。
4. ログ出力を解析したい画面に移動します。
5. アプリを閉じます。

### 結果

出力には実行時にキャプチャされたログ記録されたデータを含む可能性があります。

### 評価

機密データが出力内に見つけられた場合、そのテストケースは不合格です。
