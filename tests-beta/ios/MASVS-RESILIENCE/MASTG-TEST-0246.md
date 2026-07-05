---
platform: ios
title: 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
id: MASTG-TEST-0246
apis:
  - LAContext.canEvaluatePolicy
  - kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
type:
  - dynamic
  - hooks
weakness: MASWE-0008
best-practices: []
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0056
---

# MASTG-TEST-0246 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)

### 概要

このテストは [安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)](MASTG-TEST-0248.md) と対をなす動的テストです。

このケースでは [`LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy\(_:error:\)) API または [`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) 属性で保存されたデータをフックします。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0095.md) を使用して、関連する API をフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

### 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

### 評価

アプリが安全な画面ロックの存在を検証するための API を使用していない場合、そのテストケースは不合格です。
