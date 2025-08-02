---
masvs_category: MASVS-AUTH
platform: ios
title: ローカル認証フレームワーク (Local Authentication Framework)
---

[ローカル認証フレームワーク](https://developer.apple.com/documentation/localauthentication) はユーザーからのパスフレーズまたは Touch ID 認証を要求する機能を提供します。開発者は `LAContext` クラスの関数 `evaluatePolicy` を利用して、認証プロンプトを表示および利用できます。

二つの利用可能なポリシーでは受け入れ可能な認証形式を定義します。

- `deviceOwnerAuthentication`(Swift) または `LAPolicyDeviceOwnerAuthentication`(Objective-C): 利用可能な場合、ユーザーは Touch ID 認証を実行するよう促されます。Touch ID が有効ではない場合には、デバイスパスコードを代わりに要求されます。デバイスパスコードが有効ではない場合、ポリシー評価は失敗します。

- `deviceOwnerAuthenticationWithBiometrics` (Swift) または `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C): 認証はユーザーが Touch ID を促される生体認証に制限されます。

`evaluatePolicy` 関数はユーザーが認証に成功したかどうかを示すブール値を返します。

Apple Developer ウェブサイトでは [Swift](https://developer.apple.com/documentation/localauthentication "LocalAuthentication") と [Objective-C](https://developer.apple.com/documentation/localauthentication?language=objc "LocalAuthentication") の両方のコードサンプルを提供しています。Swift での典型的な実装は以下のようになります。

```swift
let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    // Could not evaluate policy; look at error and present an appropriate message to user
}

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please, pass authorization to enter this area") { success, evaluationError in
    guard success else {
        // User did not authenticate successfully, look at evaluationError and take appropriate action
    }

    // User authenticated successfully, take appropriate action
}
```
