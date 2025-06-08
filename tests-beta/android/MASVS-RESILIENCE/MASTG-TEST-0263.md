---
platform: android
title: StrictMode 違反のログ記録 (Logging of StrictMode Violations)
id: MASTG-TEST-0263
apis: [StrictMode]
type: [dynamic]
weakness: MASWE-0094
profiles: [R]
---

## 概要

このテストでは、アプリが本番環境で [`StrictMode`](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#strictmode) を有効にしているかどうかをチェックします。開発者が本番環境アプリでディスク I/O やネットワーク操作などのポリシー違反をログ記録することは便利ですが、`StrictMode` を有効にしたままにすると、ログに機密性の高い実装の詳細が露出し、攻撃者に悪用される可能性があります。

## 手順

1. デバイスまたはエミュレータにアプリの本番ビルドをインストールします。
2. [システムログの監視 (Monitoring System Logs)](../../../techniques/android/MASTG-TECH-0009.md) を使用して、`StrictMode` が作成するシステムログを表示します。
3. アプリを開いて実行します。

## 結果

出力には `StrictMode` に関連するログステートメントのリストを含む可能性があります。

## 評価

アプリがいずれかの `StrictMode` ポリシー違反をログ記録した場合、そのテストは不合格です。
