---
platform: android
title: バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)
id: MASTG-TEST-0216
type: [dynamic, filesystem]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0004]
---

## 概要

このテストでは、バックアップから機密ファイルを除外するように、アプリがシステムに正しく指示しているかどうかを検証します。

["Android バックアップ"](../../../Document/0x05d-Testing-Data-Storage.md#backups) は [自動バックアップ](https://developer.android.com/identity/data/autobackup) (Android 6.0 (API レベル 23) 以降) および [キーバリューバックアップ](https://developer.android.com/identity/data/keyvaluebackup) (Android 2.2 (API レベル 8) 以降) によって実装できます。自動バックアップはデフォルトで有効になっており、実装に手間がかからないため、Android で推奨されているアプローチです。

自動バックアップを使用する際に特定のファイルを除外するには、開発者はターゲット API に応じて `backup_rules.xml` (Android 11 以前の場合は `android:fullBackupContent` を使用) または `data_extraction_rules.xml` (Android 12 以降の場合は `android:dataExtractionRules` を使用) の `exclude` タグで除外ルールを明示的に定義しなければなりません。`cloud-backup` および `device-transfer` パラメータを使用して、それぞれクラウドバックアップとデバイス間転送からファイルを除外できます。キーバリューバックアップアプローチでは、開発者は [`BackupAgent`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) または [`BackupAgentHelper`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgentHelper) をセットアップし、バックアップする必要があるデータを指定します。

アプリがどのアプローチを使用したか関わらず、Android はバックアップデーモンを起動してアプリファイルをバックアップおよびリストアする方法を提供します。このデーモンをテスト目的で使用し、バックアッププロセスを開始してアプリのデータをリストアすることで、バックアップからリストアされたファイルを検証できます。

## 手順

1. デバイスを起動します。
2. デバイスにアプリをインストールします。
3. アプリを起動して使用し、さまざまなワークフローを実行しながら、可能な限り機密データを入力します。
4. バックアップデーモンを実行します。
5. アプリをアンインストールして再インストールしますが、開きはしません。
6. バックアップからデータをリストアして、リストアされたファイルのリストを取得します。

## 結果

出力にはバックアップからリストアされたファイルのリストを含む可能性があります。

## 評価

いずれかのファイルが機密であるとみなされる場合、そのテストケースは不合格です。
