---
platform: ios
title: バックアップ除外としてマークされていない機密データ (Sensitive Data Not Marked For Backup Exclusion)
id: MASTG-TEST-0215
type:
  - static
  - code
weakness: MASWE-0004
best-practices:
  - MASTG-BEST-0023
profiles:
  - L1
  - L2
  - P
knowledge:
  - MASTG-KNOW-0102
---

# MASTG-TEST-0215 バックアップ除外としてマークされていない機密データ (Sensitive Data Not Marked For Backup Exclusion)

### 概要

このテストは、アプリが `isExcludedFromBackup` を使用して、機密ファイルをバックアップから除外するようにシステムに指示しているかどうかを検証します。この API は [実際の除外を保証するものではありません](https://developer.apple.com/documentation/foundation/optimizing_your_app_s_data_for_icloud_backup/#3928527)。ドキュメントによると以下のようになります。

> 「`isExcludedFromBackup` リソース値は、除外できるファイルやディレクトリについてのガイダンスをシステムに提供するためにのみ存在します。これらのアイテムがバックアップやリストアされたデバイスに決して現れないことを保証するメカニズムではありません。」

このテストでは、バックアップに依然として存在する可能性のあるファイルをマークするために `isExcludedFromBackup` API が使用されているすべての場所を特定します。

> \[!NOTE] アプリの `/tmp` および `/Library/Caches` ディレクトリに保存されているファイルは iCloud バックアップから **除外** されます。これらのディレクトリは一時データやキャッシュデータ用に意図されており、システムは空き容量を増やすためにいつでもその内容を自動的に削除する可能性があります。したがって、これらのファイルを `isExcludedFromBackup` でマークする必要はありません。詳細については、[Apple ドキュメント](https://developer.apple.com/documentation/foundation/optimizing-your-app-s-data-for-icloud-backup#Exclude-Purgeable-Data) を参照してください。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には `isExcludedFromBackup` を使用する関数の逆アセンブルされたコードと、可能であれば、影響を受けるファイルのリストを含む可能性があります。

### 評価

`isExcludedFromBackup` API が使用され、影響を受けるいずれかのファイルが機密であるとみなされる場合、そのテストケースは不合格です。

見つかった機密ファイルについては、`isExcludedFromBackup` は除外を保証しないため、`isExcludedFromBackup` を使用することに加えて、必ず暗号化してください。
