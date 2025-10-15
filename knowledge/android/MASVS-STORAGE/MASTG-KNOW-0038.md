---
masvs_category: MASVS-STORAGE
platform: android
title: SQLCipher データベース (SQLCipher Database)
---

[SQLCipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQLCipher") ライブラリを用いて、SQLite データベースをパスワード暗号化できます。

```kotlin
var secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null)
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);")
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');")
secureDB.close()
```

データベースキーを安全に取得する方法には以下があります。

- アプリを開いた後、PIN やパスワードでデータベースを復号するようユーザーに求めます (弱いパスワードや PIN はブルートフォース攻撃に脆弱です)
- サーバーにキーを保存し、ウェブサービスからのみアクセスできるようにします (デバイスがオンラインであるときのみアプリを使用できるようにします)
