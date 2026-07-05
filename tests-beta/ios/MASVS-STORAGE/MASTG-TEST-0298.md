---
platform: ios
title: バックアップ対象のファイルの実行時監視 (Runtime Monitoring of Files Eligible for Backup)
id: MASTG-TEST-0298
type:
  - dynamic
  - hooks
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

# MASTG-TEST-0298 バックアップ対象のファイルの実行時監視 (Runtime Monitoring of Files Eligible for Backup)

### 概要

このテストは、`/var/mobile/Containers/Data/Application/$APP_ID` のアプリのデータコンテナにファイルを作成または書き込む `open`, `fopen`, `NSFileManager`, `FileHandle` などのファイルシステム API の使用をすべてログ記録し、バックアップ対象となるファイルを識別します。

`tmp` または `Library/Caches` サブディレクトリに保存されたファイルは、バックアップされないため、ログ記録されません。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0095.md) を使用して、関連する API をフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

### 結果

出力には、バックアップ対象となる、アプリが開くすべてのファイルをリストする可能性があります。

### 評価

出力内に機密ファイルを見つけた場合、そのテストケースは不合格です。
