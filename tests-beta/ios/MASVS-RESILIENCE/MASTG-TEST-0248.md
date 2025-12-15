---
platform: ios
title: 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
id: MASTG-TEST-0248
apis: [LAContext.canEvaluatePolicy, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
type: [static]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
knowledge: [MASTG-KNOW-0056]
---

## 概要

このテストでは、アプリが安全な [画面ロック (パスコードなど)](https://support.apple.com/en-us/guide/iphone/iph14a867ae/ios) が設定されたデバイス上でアプリが実行されているかどうかを検証します。

iOS では、アプリは **LocalAuthentication** フレームワークを使用して、安全な画面ロックが設定されているかどうかを判断できます。具体的には、[LAContext.canEvaluatePolicy(_:error:)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) メソッドを [.deviceOwnerAuthentication](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication) または [.deviceOwnerAuthenticationWithBiometrics](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics) ポリシーを指定して使用し、パスコードなどの認証メカニズムが利用可能かどうかをチェックできます。

**Keychain Services API** を活用するアプリは、[kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) 属性を使用して機密データにアクセスする前にパスコード認証を要求できます。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) などの静的解析ツールをアプリバイナリに対して実行して、[LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) API の使用、または [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) 属性で保存されたデータを探します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

アプリが安全な画面ロックの存在を検証するための API を使用していない場合、そのテストは不合格です。
