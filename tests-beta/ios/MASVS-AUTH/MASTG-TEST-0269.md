---
platform: ios
title: 非生体認証へのフォールバックを許可する API の実行時使用 (Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence,SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
status: draft
note: このテストは、アプリが Keychain API を使用して、ユーザー認証によって保護されるべき機密リソース (トークン、キーなど) にアクセスするかどうかを動的にチェックします。生体認証ではなくユーザーのパスコードに依存したり、生体認証が失敗した際にデバイスのパスコードにフォールバックを許可します。
---
