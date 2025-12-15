---
platform: ios
title: 非生体認証へのフォールバックを許可する API の実行時使用 (Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
profiles: [L2]
knowledge: [MASTG-KNOW-0056]
---

## 概要

このテストは [非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)](MASTG-TEST-0268.md) と対をなす動的テストです。

## 手順

1. ランタイムメソッドフック ([メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) 参照) を使用し、[`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) と特定のフラグの使用を探します。

## 結果

出力には SecAccessControlCreateWithFlags` 関数が呼び出される場所 (使用されるすべてのフラグを含む) のリストを含む可能性があります。

## 評価

保護が必要な機密データリソースに対して、アプリが `kSecAccessControlUserPresence` または `kSecAccessControlDevicePasscode` フラグを指定した `SecAccessControlCreateWithFlags` を使用している場合、そのテストは不合格です。

アプリが [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany), [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) などのより厳しいフラグを指定した `SecAccessControlCreateWithFlags` を使用して、保護が必要な機密データリソースに対するアクセスを生体認証のみに強制する場合にのみ、そのテストは合格です (`kSecAccessControlBiometryCurrentSet` が最も安全であると考えられています)。
