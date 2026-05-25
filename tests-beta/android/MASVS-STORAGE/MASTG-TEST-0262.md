---
platform: android
title: 機密データを除外しないバックアップ構成への参照 (References to Backup Configurations Not Excluding Sensitive Data)
id: MASTG-TEST-0262
type: [static, code]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0004]
profiles: [L1, L2, P]
knowledge: [MASTG-KNOW-0050]
---

## 概要

このテストでは、アプリの AndroidManifest.xml とバックアップ構成ファイルを解析して、アプリが機密ファイルをバックアップから除外するように、システムに正しく指示しているかどうかを検証します。

"Android バックアップ" ([バックアップ (Backups)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050.md)) は [自動バックアップ](https://developer.android.com/identity/data/autobackup) (Android 6.0 (API レベル 23) 以降) および [キーバリューバックアップ](https://developer.android.com/identity/data/keyvaluebackup) (Android 2.2 (API レベル 8) 以降) によって実装できます。自動バックアップはデフォルトで有効になっており、実装に手間がかからないため、Android で推奨されているアプローチです。

AndroidManifest.xml ファイルでは、`allowBackup` フラグによってアプリのデータをバックアップできるかどうかを制御します。さらに、`fullBackupContent` 属性 (Android 11 以前) または `dataExtractionRules` (Android 12 以降) を使用して、`exclude` タグでバックアップに含めるファイルと除外するファイルを指定する XML ファイルを参照できます。これらのファイルは一般的に以下のように名前付けされています。

- `backup_rules.xml` (Android 11 以前の場合は `android:fullBackupContent` を使用)
- `data_extraction_rules.xml` (Android 12 以降の場合は `android:dataExtractionRules` を使用)

`cloud-backup` および `device-transfer` パラメータを使用して、それぞれクラウドバックアップとデバイス間転送からファイルを除外できます。

キーバリューバックアップアプローチでは、開発者は [`BackupAgent`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) または [`BackupAgentHelper`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgentHelper) をセットアップし、バックアップする必要があるデータを指定します。

アプリがどのアプローチを使用したか関わらず、Android はバックアップデーモンを起動してアプリファイルをバックアップおよびリストアする方法を提供します。このデーモンをテスト目的で使用し、バックアッププロセスを開始してアプリのデータをリストアすることで、バックアップからリストアされたファイルを検証できます。

## 手順

1. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
2. [AndroidManifest の解析 (Analyzing the AndroidManifest)](../../../techniques/android/MASTG-TECH-0150.md) を使用して、AndroidManifest.xml から関連するフラグと属性を取得します。
3. [アプリパッケージの探索 (Exploring the App Package)](../../techniques/android/MASTG-TECH-0007.md) を使用して、アプリパッケージから `backup_rules.xml` または `data_extraction_rules.xml` ファイルを抽出します。

## 結果

出力には以下を明示的に示す可能性があります。

- `allowBackup` フラグが `true` または `false` に設定されているかどうか。このフラグが指定されていない場合は、デフォルトで `true` として扱われます。
- `AndroidManifest.xml` に `fullBackupContent` 属性や `dataExtractionRules` 属性が存在するかどうか。
- 存在する場合、`backup_rules.xml` ファイルまたは `data_extraction_rules.xml` ファイルの内容。

## 評価

アプリが機密データのバックアップを許可している場合、そのテストケースは不合格です。具体的には、以下の条件を満たす場合です。

- `AndroidManifest.xml` に `android:allowBackup="true"` がある場合
- `AndroidManifest.xml` に `android:fullBackupContent="@xml/backup_rules"` が宣言されていない場合 (Android 11 以前)
- `AndroidManifest.xml` に `android:dataExtractionRules="@xml/data_extraction_rules"` が宣言されていない場合 (Android 12 以降)
- `backup_rules.xml` または `data_extraction_rules.xml` が存在しないか、すべての機密ファイルを除外していない場合
