---
title: SharedPreferences API を介してアプリサンドボックスに暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via the SharedPreferences API to the App Sandbox)
platform: android
id: MASTG-TEST-0287
type: [static, dynamic]
weakness: MASWE-0006
best-practices: []
profiles: [L1, L2]
status: placeholder
note: このテストは、アプリが SharedPreferences API を使用して、アプリのサンドボックス内に暗号化されていない形式で機密データ (ユーザークレデンシャル、トークンなど) を保存しているかどうかをチェックします。これには、暗号化なしでの `SharedPreferences` の使用や、`EncryptedSharedPreferences` や同様の安全なストレージメカニズムを使用していないことのチェックを含みます。
---
