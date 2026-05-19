---
masvs_category: MASVS-PLATFORM
platform: ios
title: iOS のテキスト入力フィールドのマスク (Text Input Field Masking in iOS)
---

iOS は入力フィールドに入力されたテキストをマスクするための専用の API を用意しており、表示している文字を黒丸記号に置き換えます。これは傍観者による画面上の入力されたテキストの観察やショルダーサーフィンを防ぎ、一部の画面キャプチャやブロードキャストからテキストを保護するのに役立ちます。

## UIKit: UITextField と isSecureTextEntry

UIKit では、[`UITextField`](https://developer.apple.com/documentation/uikit/uitextfield) クラスは [`UITextInputTraits`](https://developer.apple.com/documentation/uikit/uitextinputtraits) プロトコルを採用しており、[`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) プロパティを公開しています。`true` に設定すると、このフィールドは入力された文字をマスクします。デフォルト値は `false` です。

このプロパティを設定すると、フィールドからのコピーを無効にし、キーボードからの自動テキスト入力候補も無効にします。

```swift
let passwordField = UITextField()
passwordField.isSecureTextEntry = true
```

たとえば「パスワードの表示/非表示」ボタンを実装するなど、このプロパティは実行時に切り替えることもできます。

```swift
textField.isSecureTextEntry.toggle()
```

## SwiftUI: SecureField 対 TextField

SwiftUI では、[`SecureField`](https://developer.apple.com/documentation/swiftui/securefield) はマスクしたテキスト入力のための専用コンポーネントです。[`TextField`](https://developer.apple.com/documentation/swiftui/textfield) の動きを望むが、フィールドのテキストを非表示にしたい場合に使用します。`UITextField` とは異なり、`SecureField` には設定するための `isSecureTextEntry` プロパティはありません。マスクは常に有効です。

```swift
// Masked: use SecureField
SecureField("Password", text: $password)

// Unmasked: use TextField (not appropriate for sensitive input)
TextField("Username", text: $username)
```

## その他の入力コントロール

`UITextInputTraits` を採用するコントロールは `isSecureTextEntry` を公開することもありますが、複数行テキストビューではマスクは適切ではないことがほとんどです。

`UITextField` や `SecureField` を完全にバイパスするカスタム入力コントロール (たとえば、ゲームエンジンやクロスプラットフォーム UI フレームワークで実装されているもの) はこれらのマスクメカニズムを継承せず、独自で実行する必要があります。
