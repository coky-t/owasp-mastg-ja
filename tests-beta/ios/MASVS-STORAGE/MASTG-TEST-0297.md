---
platform: ios
title: ログ記録 API を通じた機密データ露出 (Sensitive Data Exposure Through Logging APIs)
id: MASTG-TEST-0297
type:
  - static
  - code
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

# MASTG-TEST-0297 ログ記録 API を通じた機密データ露出 (Sensitive Data Exposure Through Logging APIs)

### 概要

iOS プラットフォームでは、`NSLog`, `NSAssert`, `NSCAssert`, `print`, `printf` などのログ記録 API が意図せず機密情報の漏洩につながる可能性があります。ログメッセージはコンソールに記録され、[システムログの監視 (Monitoring System Logs)](../../../techniques/ios/MASTG-TECH-0060.md) を使用してアクセスできます。デバイス上の他のアプリはこれらのログを読み取ることはできませんが、データ漏洩の可能性があるため、直接ログ記録することは一般的に推奨されません。

このテストでは、静的解析を使用して、アプリが入力として機密データを取得するログ記録 API を含むかどうかを検証します。

このテストはログ記録される機密データに焦点を当てています。ログを通じて公開される実装の詳細を具体的な対象とするテストについては、[ログ記録 API を通じた実装詳細の露出 (Implementation Details Exposure Through Logging APIs)](https://github.com/coky-t/owasp-mastg-ja/blob/master/tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0358.md) および [ログ内の実装詳細の露出 (Implementation Details Exposure in Logs)](https://github.com/coky-t/owasp-mastg-ja/blob/master/tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0359.md) を参照してください。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力にはログ記録関数やその他の関連するログ記録参照の位置を含む可能性があります。逆コンパイルされたコードをチェックして、機密データを入力として受け取るかどうかを検証します。

### 評価

アプリが、機密データをログ記録する、実装されたログ記録パスを含む場合、そのテストケースは不合格です。
