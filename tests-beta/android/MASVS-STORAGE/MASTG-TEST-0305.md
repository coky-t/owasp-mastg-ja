---
title: DataStore 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via DataStore)
platform: android
id: MASTG-TEST-0305
type: [static, dynamic]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
status: placeholder
note: このテストは、アプリが最新の Jetpack DataStore API (Preferences DataStore や Proto DataStore) を使用して、機密データ (トークン、PII など) を暗号化せずに保存しているかどうかをチェックします。データの完全性と機密性を保護するための安全なシリアライザやメカニズムがないことを確認します。
---
