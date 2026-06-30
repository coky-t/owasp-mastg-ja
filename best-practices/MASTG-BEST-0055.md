---
title: カスタム URL スキームハンドラでソースアプリケーションを検証する (Validate Source Application in Custom URL Scheme Handlers)
alias: validate-source-application-in-custom-url-scheme-handlers
id: MASTG-BEST-0055
platform: ios
knowledge: [MASTG-KNOW-0079]
---

カスタム URL スキームが特権的あるいは不可逆なアクションをトリガーする場合、リクエストを処理する前に [`UIOpenURLContext.options`](https://developer.apple.com/documentation/uikit/uiopenurl/options) から [`sourceApplication`](https://developer.apple.com/documentation/uikit/uiscene/connectionoptions/sourceapplication) をチェックします。これは呼び出し元アプリのバンドル ID を許可リストに対して検証することで可能です。

```swift
let allowedSources: Set<String> = ["com.example.myapp", "com.example.companion"]

guard let source = context.options.sourceApplication,
      allowedSources.contains(source) else {
    return
}
```

## 両方の URL デリバリパスをチェックする

Scene ライフサイクルを使用する場合、URL は二つのパスを通じて到着する可能性があります。コールドローンチでの [`scene(_:willConnectTo:options:)`](https://developer.apple.com/documentation/uikit/uiscenedelegate/scene(_:willconnectto:options:)) と、ウォームオープンでの [`scene(_:openURLContexts:)`](https://developer.apple.com/documentation/uikit/uiscenedelegate/scene(_:openurlcontexts:)) です。一つのパスが保護されていない状態になることを避けるために、両方のハンドラで `sourceApplication` を検証します。

## Apple Developer Team の制限事項

Apple は呼び出し元アプリが同じ [Apple Developer Team](https://developer.apple.com/help/account/manage-your-team/about-the-team-id/) に属している場合にのみ `sourceApplication` を設定します。他チームのアプリやシステムアプリ (Safari、メモなど) からのアプリでは `sourceApplication` を `nil` に設定します。これは、ソースバリデーションが、任意のサードパーティの呼び出し元を識別するためではなく、URL スキームが自身のアプリスイートをトリガーすることに限定するために最も有用です。

> [!NOTE]
> [`.onOpenURL`](https://developer.apple.com/documentation/swiftui/view/onopenurl(perform:)) を用いる純粋な SwiftUI を使用するアプリでは、`sourceApplication` は利用できません。ソースバリデーションが必要とされる場合、代わりに `SceneDelegate` とともに Scene ライフサイクルを使用します。
