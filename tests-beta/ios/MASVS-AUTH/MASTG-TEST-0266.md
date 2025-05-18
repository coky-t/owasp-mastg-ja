---
platform: ios
title: イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)
id: MASTG-TEST-0266
apis: [LAContext.evaluatePolicy]
type: [static]
weakness: MASWE-0044
status: draft
note: このテストは、アプリが LocalAuthentication API を使用して、ユーザー認証によって保護されるべき機密リソース (トークン、キーなど) にアクセスするかどうかを静的にチェックします。Keychain API を使用したりユーザーの存在を要求するのではなく、LocalAuthentication API のみに依存します。
---
