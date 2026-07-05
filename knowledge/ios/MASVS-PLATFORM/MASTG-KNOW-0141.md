---
masvs_category: MASVS-PLATFORM
platform: ios
title: カスタムキーボード (Custom Keyboards)
available_since: 8
---

[カスタムキーボード](https://developer.apple.com/documentation/uikit/creating-a-custom-keyboard) は、デバイス上のすべてのアプリにわたってシステムキーボードを置き換えるアプリ拡張 ([App Extension (App extensions)](MASTG-KNOW-0082.md) を参照) です。ユーザーはそれを含むアプリを通じてインストールを行い、明示的に **設定** (**一般 > キーボード > キーボード**) で有効にする必要があります。

デフォルトでは、[カスタムキーボードは「フルアクセス」なしで実行](https://developer.apple.com/documentation/uikit/configuring-open-access-for-a-custom-keyboard) し、ネットワークリクエストの作成や共有コンテナへのアクセスを防ぎます。ユーザーは設定の「フルアクセス」を付与できます。キーボードが [`RequestsOpenAccess`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsextension/nsextensionattributes/requestsopenaccess) キーを介して要求し、`UIInputViewController` の [`hasFullAccess`](https://developer.apple.com/documentation/uikit/uiinputviewcontroller/hasfullaccess) プロパティを通じてそれを有するかどうかをチェックできます。

iOS はどのキーボードがアプリのテキストフィールドを処理するかを制御するために以下の二つを用意しています。

- [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) 特性が `true` である `UITextField` や `UITextView` (または SwiftUI `SecureField`) では常にシステムキーボードを使用します。セキュアなフィールドではサードパーティキーボードが表示されないため、それらが入力された文字を受け取ることはありません。
- アプリは `UIApplicationDelegate` の [`application(_:shouldAllowExtensionPointIdentifier:)`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application(_:shouldallowextensionpointidentifier:)) を実装し、`UIApplicationKeyboardExtensionPointIdentifier` (`com.apple.keyboard-service`) に対して `false` を返すことで、アプリ全体にわたってカスタムキーボード拡張を拒否できます。それにより、ユーザーがインストールしたキーボードに関わらず、システムはアプリ全体にわたって組み込みキーボードを使用します。
