---
title: テキスト入力フィールド内の機密データをマスクする (Mask Sensitive Data in Text Input Fields)
alias: mask-sensitive-data-in-text-input-fields-ios
id: MASTG-BEST-0044
platform: ios
knowledge: [MASTG-KNOW-0098]
---

パスワード、PIN、OTP などの機密情報を扱うテキスト入力フィールドについては、入力されたテキストが視覚的にマスクされ、傍観者や画面キャプチャツールによって開示されないようにします。

## UIKit

機密データをキャプチャする `UITextField` には [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) を `true` に設定します。これは入力した文字を黒点記号 (•) に置き換え、テキストをプレーンテキストで表示することを防ぎます。

```swift
let passwordField = UITextField()
passwordField.isSecureTextEntry = true
```

## SwiftUI

パスワード、PIN、OTP を扱う入力には `TextField` の代わりに [`SecureField`](https://developer.apple.com/documentation/swiftui/securefield) を使用します。`SecureField` はユーザー入力したコンテンツを自動的にマスクします。

```swift
SecureField("Password", text: $password)
```

> [!NOTE]
> アプリケーション層でマスクされたフィールドのように見せるスタイル設定をするつもりであっても、機密性の高い入力にはプレーンな `TextField` を使用してはいけません。これはシステムが提供する安全なテキスト入力メカニズムと同じレベルの保護を提供しないためです。
