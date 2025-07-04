---
title: アプリデータのバックアップと復元の実行 (Performing a Backup and Restore of App Data)
platform: android 
---

## バックアップマネージャの使用 (ADB シェル経由)

[バックアップマネージャ (`adb shell bmgr`)](https://developer.android.com/identity/data/testingbackup#TestingBackup) を実行します。

{{ https://github.com/OWASP/owasp-mastg/blob/master/utils/mastg-android-backup-bmgr.sh }}

クラウドトランスポートバリアントを使用する場合、各アプリのバックアップはユーザーの Google ドライブで個別に管理および保存されます。このケースではローカルトランスポートバリアントを対象としており、`bmgr` が各アプリのバックアップデータをデバイス上の `/data/data/com.android.localtransport/files/` ディレクトリ内の個別の `.ab` ファイルに保存します。ファイルを抽出するには、以下を実行します。

```sh
adb root
adb pull /data/data/com.android.localtransport/files/1/_full/org.owasp.mastestapp org.owasp.mastestapp.ab
tar xvf org.owasp.mastestapp.ab
```

抽出されたバックアップディレクトリ (`apps/`) は現在の作業ディレクトリに保存されます。これを検査する方法については、[アプリのバックアップデータの検査 (Inspecting an App's Backup Data)](MASTG-TECH-0127.md) を参照してください。

## ADB バックアップの使用

!!! 警告
    `adb backup` は [Android 12 以降で制限](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions) されており、AndroidManifest.xml に `android:debuggable=true` が必要です。

`adb backup` を実行してアプリデータをバックアップできます。_データのバックアップ_ オプションを選択して、デバイスからバックアップを承認します。バックアッププロセスが終了すると、作業ディレクトリに _.ab_ ファイルがあります。

{{ https://github.com/OWASP/owasp-mastg/blob/master/utils/mastg-android-backup-adb.sh }}

抽出されたバックアップディレクトリ (`apps/`) は現在の作業ディレクトリに保存されます。これを検査する方法については、[アプリのバックアップデータの検査 (Inspecting an App's Backup Data)](MASTG-TECH-0127.md) を参照してください。

**注:** エミュレータと物理デバイスでは動作が異なることがあります。

## Android Backup Extractor の使用

[Android Backup Extractor](https://github.com/nelenkov/android-backup-extractor) を使用してバックアップデータを抽出できます。詳細については GitHub リポジトリをご覧ください。
