--- 
title: アプリのバックアップデータの検査 (Inspecting an App's Backup Data)
platform: android 
---

Android アプリのバックアップデータを検査して、機密データがバックアップに含まれていないことを検証できます。このテクニックはアプリがバックアップから機密データを正しく除外していることを検証するのに役立ちます。

## ADB バックアップで作成されるバックアップ

Android のバックアップは、特別にフォーマットされた TAR アーカイブである `.ab` ファイルに保存されます。[アプリデータのバックアップと復元の実行 (Performing a Backup and Restore of App Data)](MASTG-TECH-0128.md) の手順に従った場合、作業ディレクトリに `apps/` ディレクトリがあるはずです。このディレクトリには抽出されたバックアップデータを含みます。

ファイルはその意味上のオリジンに応じたトップレベルディレクトリ内に保存されます。

- `apps/pkgname/a/`: アプリケーションの .apk ファイル自体
- `apps/pkgname/obb/`: アプリケーションに関連する .obb コンテナ
- `apps/pkgname/f/`: `getFilesDir()` の場所をルートとするサブツリー
- `apps/pkgname/db/`: `getDatabasePath()` の親をルートとするサブツリー
- `apps/pkgname/sp/`: `getSharedPrefsFile()` の親をルートとするサブツリー
- `apps/pkgname/r/`: アプリのファイルツリーのルートから相対的に保存されたファイル
- `apps/pkgname/c/`: アプリの `getCacheDir()` ツリー用に予約済み。保存されません。
