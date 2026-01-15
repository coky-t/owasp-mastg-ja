---
masvs_category: MASVS-AUTH
platform: ios
title: キーチェーンサービス (Keychain Services)
---

ローカル認証を実装するには iOS keychain API を使用できます (そして、使用すべきです) 。このプロセスでは、アプリは秘密の認証トークンかキーチェーンでユーザーを識別する別の秘密データを格納します。リモートサービスを認証するには、ユーザーは秘密のデータを取得するためにパスフレーズまたは指紋を使用してキーチェーンをアンロックする必要があります。

キーチェーンは特別な `SecAccessControl` 属性でアイテムを保存することができます。これはユーザーが Touch ID 認証 (またはパスコード、属性パラメータによりそのようなフォールバックが許可されている場合) をパスした後でのみ、キーチェーンからアイテムへのアクセスを許可します。

> [!NOTE]
> macOS や Android とは異なり、iOS は現時点 (iOS 12) ではキーチェーンのアイテムのアクセシビリティの一過性をサポートしていません。キーチェーンに入るときに追加のセキュリティチェックがない場合 (例えば `kSecAccessControlUserPresence` などが設定されている) 、デバイスがアンロックされると、鍵はアクセス可能となります。

以下の例では、文字列 "test_strong_password" をキーチェーンに保存します。この文字列は、パスコードが設定されている間 (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` パラメータ)、かつ現在登録されている指のみでの Touch ID 認証後 (`SecAccessControlCreateFlags.biometryCurrentSet` パラメータ) に、現在のデバイス上でのみアクセス可能です。

```swift
// 1. 認証設定を表す AccessControl オブジェクトを作成する

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                          SecAccessControlCreateFlags.biometryCurrentSet,
                                                          &error) else {
    // failed to create AccessControl object

    return
}

// 2. キーチェーンサービスクエリを定義する。kSecAttrAccessControl は kSecAttrAccessible 属性と相互排他的であることに注意する

var query: [String: Any] = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. アイテムを保存する

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
    // successfully saved
} else {
    // error while saving
}

// 4. これで保存したアイテムをキーチェーンからリクエストできます。キーチェーンサービスはユーザーに認証ダイアログを表示し、適切な指紋が提供されたかどうかに応じてデータまたは nil を返します。

// 5. クエリを定義する
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 6. アイテムを取得する
var queryResult: AnyObject?
let status = withUnsafeMutablePointer(to: &queryResult) {
    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
}

if status == noErr {
    let password = String(data: queryResult as! Data, encoding: .utf8)!
    // パスワードの取得に成功
} else {
    // 認証がパスしなかった
}
```
