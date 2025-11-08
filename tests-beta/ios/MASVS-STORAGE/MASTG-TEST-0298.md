---
platform: ios
title: バックアップ対象のファイルの実行時監視 (Runtime Monitoring of Files Eligible for Backup)
id: MASTG-TEST-0298
type: [dynamic]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0023]
profiles: [L1, L2, P]
---

## 概要

このテストは、`/var/mobile/Containers/Data/Application/$APP_ID` のアプリのデータコンテナに書き込まれたすべてのファイルをログ記録し、バックアップ対象となるファイルを識別します。`tmp` または `Library/Caches` サブディレクトリに保存されたファイルは、バックアップされないため、ログ記録されません。

## 手順

1. ランタイムメソッドフック ([メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) 参照) を使用し、ファイルを作成や書き込みを行う `open`, `fopen`, `NSFileManager`, `FileHandle` などのファイルシステム API の使用を探します。
2. アプリを実行して、ファイル作成と書き込みをトリガーします。

## 結果

出力には、バックアップ対象となる、アプリが開くすべてのファイルをリストする可能性があります。

## 評価

出力内に機密ファイルを見つけた場合、そのテストケースは不合格です。
