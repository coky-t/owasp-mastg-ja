---
title: Android Room Database 経由で暗号化されずに保存される機密データへの参照 (References to Sensitive Data Unencrypted via Android Room Database)
platform: android
id: MASTG-TEST-0304
type: [static, code]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0037]
status: placeholder
note: このテストは、アプリがデフォルトの SQLite API (`SQLiteOpenHelper`, `context.openOrCreateDatabase` など) を使用して、機密データ (トークン、PII など) をアプリのサンドボックス内の暗号化されていないデータベースファイルに保存しているかどうかをチェックします。SQLCipher や暗号化されたデータベースなどの安全な代替手段がないことを確認します。
---
