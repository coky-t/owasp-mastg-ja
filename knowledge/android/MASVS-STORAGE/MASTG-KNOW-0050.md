---
masvs_category: MASVS-STORAGE
platform: android
title: バックアップ (Backups)
---

[Android のバックアップ](https://developer.android.com/identity/data/backup) は通常、インストールされているすべてのアプリのデータと設定のコピーを含みます。多様なエコシステムを考慮して、Android は多くのバックアップオプションをサポートしています。

- 既成の Android にはビルトインの USB バックアップ機能があります。USB デバッグが有効になっている場合、`adb backup` コマンド ([Android 12 以降では制限されており](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)、AndroidManifest.xml で `android:debuggable=true` を必要とします) を使用して、完全なデータバックアップとアプリのデータディレクトリのバックアップを作成します。

- Google は、すべてのアプリデータを Google のサーバーにバックアップする「データのバックアップ」機能を提供しています。

- アプリ開発者は二つのバックアップ API を利用できます。
    - [Key/Value Backup](https://developer.android.com/guide/topics/data/keyvaluebackup.html "Key/Value Backup") (Backup API または Android Backup Service) は Android Backup Service クラウドにアップロードします。

    - [Auto Backup for Apps](https://developer.android.com/guide/topics/data/autobackup.html "Auto Backup for Apps"): Android 6.0 (API レベル 23) 以降では、Google は「アプリの自動バックアップ機能」を追加しました。この機能は最大 25 MB のアプリデータをユーザーの Google ドライブアカウントと自動的に同期します。

- OEM は追加オプションを提供する可能性があります。たとえば、HTC デバイスには "HTC Backup" オプションがあり、アクティベートすると日ごとにクラウドにバックアップを実行します。

アプリは、機密性の高いユーザーデータがこれらのバックアップ内に存在しないように注意を払う必要があります。これは攻撃者がそれを抽出できる可能性があるためです。

## [adb](../../../tools/android/MASTG-TOOL-0004.md) バックアップサポート

Android はすべてのアプリケーションデータをバックアップするための [`allowBackup`](https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup "allowBackup attribute") という属性を提供しています。この属性は `AndroidManifest.xml` ファイルに設定します。この属性の値が **true** である場合、デバイスはユーザーが `$ adb backup` コマンド ([Android 12 以降では制限されている](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)) を介して [adb](../../../tools/android/MASTG-TOOL-0004.md) でアプリケーションをバックアップすることを許可します。

アプリデータのバックアップを禁止するには、`android:allowBackup` 属性を **false** に設定します。この属性が利用できない場合、allowBackup 設定はデフォルトで有効になり、バックアップを手動で無効にしなければなりません。

### !!! 注記
デバイスが暗号化されている場合、バックアップファイルも暗号化されます。
