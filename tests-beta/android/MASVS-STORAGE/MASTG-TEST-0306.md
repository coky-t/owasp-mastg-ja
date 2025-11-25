---
title: Android Room DB 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via Android Room DB)
platform: android
id: MASTG-TEST-0306
type: [static, dynamic]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
status: placeholder
note: このテストは、アプリが Android Room Persistence Library を使用して、機密データ (トークン、PII など) を暗号化レイヤ (SQLCipher など) を統合せずに保存しているかどうかをチェックします。データベースファイルがアプリのプライベートサンドボックス内にプレーンテキストで保存されていることを確認します。
---
