---
masvs_category: MASVS-STORAGE
platform: android
title: SQLite データベース (SQLite Database)
---

SQLite は `.db` ファイルにデータを保存する SQL データベースエンジンです。Android SDK は SQLite データベースについて [ビルトインサポート](https://developer.android.com/training/data-storage/sqlite "SQLite Documentation") しています。データベースを管理するために使用されるメインパッケージは `android.database.sqlite` です。

たとえば、以下のコードを使用して、アクティビティ内で機密情報を保存しているかもしれません。

```kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
notSoSecure.close()
```

そのアクティビティが呼び出されると、提供されたデータでデータベースファイル `privateNotSoSecure` が作成され、クリアテキストファイル `/data/data/<package-name>/databases/privateNotSoSecure` に保存されます。

データベースのディレクトリには SQLite データベース以外にも以下のいくつかのファイルを含むことがあります。

- [ジャーナルファイル](https://www.sqlite.org/tempfiles.html "SQLite Journal files"): これらはアトミックコミットとロールバックを実装するために使用される一時ファイルです。
- [ロックファイル](https://www.sqlite.org/lockingv3.html "SQLite Lock Files"): ロックファイルは、SQLite の並行性を向上し、書き込み枯渇問題を軽減するために設計された、ロックおよびジャーナル機能の一部です。

機密情報は暗号化されていない SQLite データベースに保存してはいけません。
