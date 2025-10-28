---
platform: ios
title: ログへの機密データの挿入 (Insertion of Sensitive Data into Logs)
id: MASTG-TEST-0297
type: [static]
weakness: MASWE-0001
prerequisites:
- identify-sensitive-data
best-practices: [MASTG-BEST-0022]
profiles: [L1, L2]
---

## 概要

iOS プラットフォームでは、`NSLog`, `NSAssert`, `NSCAssert`, `print`, `printf` などのログ記録 API が意図せず機密情報の漏洩につながる可能性があります。ログメッセージはコンソールに記録され、[システムログの監視 (Monitoring System Logs)](../../../techniques/ios/MASTG-TECH-0060.md) を使用してアクセスできます。デバイス上の他のアプリはこれらのログを読み取ることはできませんが、データ漏洩の可能性があるため、直接ログ記録することは一般的に推奨されません。

このテストでは、静的解析を使用して、アプリに機密データを取得するログ記録 API があるかどうかを検証します。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールをアプリバイナリに対して実行して、ログ記録 API の使用を探します。

## 結果

出力にはすべてのログ記録関数の位置を含む可能性があります。逆コンパイルされたコードをチェックして、機密データを入力として受け取るかどうかを検証します。

## 評価

機密データをログ記録するログ記録 API の使用を見つけた場合、そのテストケースは不合格です。
