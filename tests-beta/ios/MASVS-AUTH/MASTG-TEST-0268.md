---
platform: ios
title: 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0045
status: draft
note: このテストは、アプリが Keychain API を使用して、ユーザー認証によって保護されるべき機密リソース (トークン、キーなど) にアクセスするかどうかを静的にチェックします。生体認証ではなくユーザーのパスコードに依存したり、生体認証が失敗した際にデバイスのパスコードにフォールバックを許可します。
---
