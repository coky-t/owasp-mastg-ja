---
platform: ios
title: バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)
id: MASTG-TEST-0215
type: [static, filesystem]
weakness: MASWE-0004
---

## 概要

このテストでは、バックアップから機密ファイルを除外するように、アプリがシステムに正しく指示しているかどうかを検証します。

アプリコンテナの `/tmp` および `/Library/Caches` サブディレクトリにあるファイルは iCloud バックアップから除外されます。アプリコンテナ内のその他の場所にあるファイルやディレクトリについては、iOS は [`isExcludedFromBackup`](https://developer.apple.com/documentation/foundation/urlresourcevalues/1780002-isexcludedfrombackup) API を提供し、特定のファイルやディレクトリをバックアップしないようにシステムをガイドします。ただし、この API は [実際の除外を保証するものではありません](https://developer.apple.com/documentation/foundation/optimizing_your_app_s_data_for_icloud_backup/#3928527)。

> 「`isExcludedFromBackup` リソース値は、除外できるファイルやディレクトリについてのガイダンスをシステムに提供するためにのみ存在します。これらのアイテムがバックアップやリストアされたデバイスに決して現れないことを保証するメカニズムではありません。」

したがって、バックアップからファイルを適切に保護する唯一の方法は、ファイルを暗号化することです。

## 手順

1. アプリバイナリに対して [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールを実行するか、[Frida for iOS](../../../tools/ios/MASTG-TOOL-0039.md) などの動的解析ツールを使用して、`isExcludedFromBackup` API の使用を探します。

## 結果

出力には `isExcludedFromBackup` を使用する関数の逆アセンブルされたコードと、可能であれば影響を受けるファイルのリストを含む可能性があります。

## 評価

ソースコード内に `isExcludedFromBackup` の使用が見つかり、影響を受けるいずれかのファイルが機密であるとみなされる場合、そのテストケースは不合格です。

見つかった機密ファイルについては、`isExcludedFromBackup` は除外を保証しないため、`isExcludedFromBackup` を使用することに加えて、必ず暗号化してください。
