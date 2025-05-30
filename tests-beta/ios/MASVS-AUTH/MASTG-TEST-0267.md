---
platform: ios
title: イベントバウンド型生体認証の実行時使用 (Runtime Use Of Event-Bound Biometric Authentication)
id: MASTG-TEST-0267
apis: [LAContext.evaluatePolicy]
type: [dynamic]
weakness: MASWE-0044
best-practices: []
---

## 概要

このテストは [イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)](MASTG-TEST-0266) と対をなす動的テストです。

## 手順

1. ランタイムメソッドフック ([メソッドフック (Method Hooking)](techniques/ios/MASTG-TECH-0095.md) 参照) を使用し、 [LAContext.evaluatePolicy(...)](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)) と [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) の使用をすべてのフラグを含めて探します。

## 結果

出力には`LAContext.evaluatePolicy` と `SecAccessControlCreateWithFlags` 関数が呼び出される場所 (使用されるすべてのフラグを含む) のリストを含む可能性があります。

## 評価

保護する価値のある機密データリソースごとに、以下が該当する場合、そのテストは不合格です。

- `LAContext.evaluatePolicy` が明示的に使用されている。
- [可能なフラグのいずれか](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) でユーザーの存在を要求する `SecAccessControlCreateWithFlags` の呼び出しがない。
