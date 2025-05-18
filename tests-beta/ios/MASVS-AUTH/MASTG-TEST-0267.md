---
platform: ios
title: イベントバウンド型生体認証の実行時使用 (Runtime Use Of Event-Bound Biometric Authentication)
id: MASTG-TEST-0267
apis: [LAContext.evaluatePolicy]
type: [dynamic]
weakness: MASWE-0044
best-practices: []
status: draft
note: このテストは、アプリが LocalAuthentication API を使用して、ユーザー認証によって保護されるべき機密リソース (トークン、キーなど) にアクセスするかどうかを動的にチェックします。Keychain API を使用したりユーザーの存在を要求するのではなく、LocalAuthentication API のみに依存します。
---
