---
masvs_category: MASVS-PLATFORM
platform: ios
title: キーチェーンアクセスグループ (Keychain Access Groups)
---

キーチェーンアクセスグループは同じ開発者チームによる複数のアプリがキーチェーンアイテムを共有することを許可します。共有アクセスグループなしでは、キーチェーンアイテムはアプリのデフォルトキーチェーンアクセスグループへのプライベートとなります。

## エンタイトルメント

アプリは [`keychain-access-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups) エンタイトルメントにそのキーチェーンアクセスグループを宣言します。このエンタイトルメントの値はグループ識別子の配列であり、アプリの App ID プレフィックス (通常はチーム ID) がそれぞれ接頭辞となります (たとえば `TeamID.com.example.shared`)。

Xcode はアプリのデフォルトアクセスグループ (通常は `TeamID.bundleID`) を自動的に追加します。追加の共有グループは [キーチェーン共有機能](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing) を通じて明示的に宣言する必要があります。

## キーチェーンアイテムの共有

アイテムを共有アクセスグループに格納するには、クエリ辞書に [`kSecAttrAccessGroup`](https://developer.apple.com/documentation/security/ksecattraccessgroup) キーを含めます。

```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessGroup as String: "TeamID.com.example.shared",
    kSecAttrAccount as String: "username",
    kSecValueData as String: passwordData
]
SecItemAdd(query as CFDictionary, nil)
```

そのエンタイトルメントに同じアクセスグループを持つ任意のアプリはそのグループに格納されているアイテムにアクセスでき、そのアイテムの他のキーチェーン属性とアクセス制御の影響を受けます。`kSecAttrAccessGroup` が省略されている場合、そのアイテムはアプリのデフォルトアクセスグループに格納されます。

## スコープと制約

- キーチェーンアクセスグループはアプリの App ID プレフィックスにスコープされ、一般的に開発者チームに紐づいています。異なるチームのアプリは通常、キーチェーンアクセスグループを共有できません。
- 共有アクセスグループに格納されたアイテムはそのグループを宣言しているすべてのアプリにアクセス可能であり、そのアイテムのアクセシビリティやアクセス制御設定の影響を受けます。
- アクセスグループは、キーチェーンアイテムを作成する際、`kSecAttrAccessGroup` に `SecItemAdd` を指定することで設定されます。
- キーチェーンアイテムは、アクセスグループとは別に、iOS キーチェーンのデータ保護クラス (`kSecAttrAccessible*`) によって保護されます。
- 共有キーチェーンアイテムは最小限にとどめる必要があります。そのグループの任意のアプリや拡張がそれらを読み取り、更新、削除できる可能性があるためです。
