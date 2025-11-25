---
title: SQLite 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via SQLite)
platform: android
id: MASTG-TEST-0304
type: [static, dynamic]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
status: placeholder
note: このテストは、アプリがデフォルトの SQLite API (例: `SQLiteOpenHelper`, `context.openOrCreateDatabase`) を使用して、機密データ (例: トークン、PII) をアプリのサンドボックス内の暗号化されていないデータベースファイルに保存しているかどうかをチェックします。SQLCipher や暗号化されたデータベースなどの安全な代替手段がないことを確認します。
---
