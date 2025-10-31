---
masvs_category: MASVS-STORAGE
platform: ios
title: ファイルシステム API (File System APIs)
---

FileManager インタフェースはファイルシステムの内容を確認および変更できます。[`createFile(atPath:contents:attributes:)`](https://developer.apple.com/documentation/foundation/filemanager/createfile(atpath:contents:attributes:)) を使用して、ファイルを作成して書き込みを行うことができます。

以下の例は、アプリのドキュメントディレクトリにファイルを完全に保護して保存する方法を示しています。つまり、ファイルは暗号化され、デバイスがロック解除されている場合にのみアクセスできます。

```swift
FileManager.default.createFile(
    atPath: filePath,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

詳細については Apple 開発者ドキュメント ["Encrypting Your App's Files"](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files "Encrypting Your App's Files") をご覧ください。
