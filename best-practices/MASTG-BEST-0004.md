---
title: バックアップから機密データを除外する (Exclude Sensitive Data from Backups)
alias: exclude-sensitive-data-from-backups
id: MASTG-BEST-0004
platform: android
knowledge: [MASTG-KNOW-0050]
---

見つかった機密ファイルについては、バックアップから除外するように指示します。

- 自動バックアップを使用している場合、ターゲット API に応じて `backup_rules.xml` (Android 11 以前の場合は `android:fullBackupContent` を使用) または `data_extraction_rules.xml` (Android 12 以降の場合は `android:dataExtractionRules` を使用) の `exclude` タグでマークします。必ず `cloud-backup` と `device-transfer` の両方のパラメータを使用してください。
- キーバリューアプローチを使用している場合、それに応じて [BackupAgent](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) をセットアップします。

詳細については ["Security recommendations for backups - Mitigations"](https://developer.android.com/privacy-and-security/risks/backup-best-practices#security-recommendations-for-backups-mitigations) を参照してください。
