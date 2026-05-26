---
platform: ios
title: 非生体認証へのフォールバックを許可する API の実行時使用 (Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [dynamic, hooks]
weakness: MASWE-0045
profiles: [L2]
knowledge: [MASTG-KNOW-0056]
---

## 概要

このテストは [非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)](MASTG-TEST-0268.md) と対をなす動的テストです。

このケースでは [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) とその特定のフラグをフックします。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) を使用して、関連する API をフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

## 結果

出力には SecAccessControlCreateWithFlags` 関数が呼び出される場所 (使用されるすべてのフラグを含む) のリストを含む可能性があります。

## 評価

保護が必要な機密データリソースに対して、アプリが `kSecAccessControlUserPresence` または `kSecAccessControlDevicePasscode` フラグを指定した `SecAccessControlCreateWithFlags` を使用している場合、そのテストケースは不合格です。
