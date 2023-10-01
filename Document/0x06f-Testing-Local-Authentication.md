---
masvs_category: MASVS-AUTH
platform: ios
---

# iOS のローカル認証

## 概要

ローカル認証では、アプリはデバイス上でローカルに保存された資格情報に対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、または顔や指紋などの生体特性を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、これはユーザーがより便利にリモートサービスでの既存のセッションを再開するため、またはある重要な機能を保護するためのステップアップ認証の手段として行われます。

["モバイルアプリの認証アーキテクチャ"](0x04e-Testing-Authentication-and-Session-Management.md) の章で前述しているように、テスト技術者はローカル認証が常にリモートエンドポイントで実行されることや暗号プリミティブに基づいている必要があることに注意します。認証プロセスからデータが返らない場合、攻撃者は簡単にローカル認証をバイパスできます。

アプリにローカル認証を統合するためのさまざまな方法が用意されています。[Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") では開発者がユーザーへの認証ダイアログを拡張するための一連の API が提供されています。リモートサービスに接続するコンテキストでは、ローカル認証を実装するに [キーチェーン](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Keychain Services") を利用することが可能であり (および推奨され) ます。

iOS での指紋認証は _Touch ID_ として知られています。指紋 ID センサーは [SecureEnclave security coprocessor](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") により操作され、指紋データをシステムの他の部分に開示することはありません。Touch ID の次に、Apple は顔認識に基づく認証を可能にする _Face ID_ を導入しました。いずれもアプリケーションレベルで、データを格納し、データを格納する実際の手法として、似たような API を使用します (例えば、顔データと指紋関連データが異なります) 。

開発者には Touch ID/FaceID 認証を組み込むために二つの選択肢があります。

- `LocalAuthentication.framework` は上位レベルの API であり、Touch ID 経由でユーザーを認証するために使用できます。アプリは登録された指紋に関連付けられたデータにアクセスすることはできません。認証が成功したかどうかだけが通知されます。
- `Security.framework` は下位レベルの API であり、[keychain Services](https://developer.apple.com/documentation/security/keychain_services "keychain Services") にアクセスします。アプリが生体認証である機密データを保護する必要がある場合、アクセス制御はシステムレベルで管理され、簡単にはバイパスできないため、これはセキュアな選択肢です。`Security.framework` には C API がありますが、いくつかの [オープンソースラッパーを利用](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The keychain and Touch ID") して、キーチェーンへのアクセスを NSUserDefaults のように簡単に行えます。`Security.framework` は `LocalAuthentication.framework` の基礎にあります。Apple は可能であれば上位レベル API をデフォルトとすることを推奨しています。

`LocalAuthentication.framework` または `Security.framework` のいずれかを使用すると、ブール値を返すだけで処理を続けるデータがないため、攻撃者がバイパスできるコントロールになることに注意します。詳細については [Don't touch me that way, by David Lindner et al](https://www.youtube.com/watch?v=XhXIHVGCFFM "Don\'t Touch Me That Way - David Lindner") を参照してください。

### ローカル認証フレームワーク

ローカル認証フレームワークはユーザーからのパスフレーズまたは Touch ID 認証を要求する機能を提供します。開発者は `LAContext` クラスの関数 `evaluatePolicy` を利用して、認証プロンプトを表示および利用できます。

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

### ローカル認証にキーチェーンサービスを使用する

ローカル認証を実装するには iOS keychain API を使用できます (そして、使用すべきです) 。このプロセスでは、アプリは秘密の認証トークンかキーチェーンでユーザーを識別する別の秘密データを格納します。リモートサービスを認証するには、ユーザーは秘密のデータを取得するためにパスフレーズまたは指紋を使用してキーチェーンをアンロックする必要があります。

キーチェーンは特別な `SecAccessControl` 属性でアイテムを保存することができます。これはユーザーが Touch ID 認証 (またはパスコード、属性パラメータによりそのようなフォールバックが許可されている場合) をパスした後でのみ、キーチェーンからアイテムへのアクセスを許可します。

以下の例では、文字列 "test_strong_password" をキーチェーンに保存します。この文字列は、パスコードが設定されている間 (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` パラメータ)、かつ現在登録されている指のみでの Touch ID 認証後 (`SecAccessControlCreateFlags.biometryCurrentSet パラメータ`) に、現在のデバイス上でのみアクセス可能です。

### Swift

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

### Objective-C

```objectivec
// 1. 認証設定を表す AccessControl オブジェクトを作成する
CFErrorRef *err = nil;

SecAccessControlRef sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecAccessControlUserPresence,
    err);

// 2. キーチェーンサービスクエリを定義する。kSecAttrAccessControl は kSecAttrAccessible 属性と相互排他的であることに注意する
NSDictionary* query = @{
    (_ _bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecAttrAccount: @"OWASP Account",
    (__bridge id)kSecValueData: [@"test_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef
};

// 3. アイテムを保存する
OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

if (status == noErr) {
    // successfully saved
} else {
    // error while saving
}

// 4. これで保存したアイテムをキーチェーンからリクエストできます。キーチェーンサービスはユーザーに認証ダイアログを表示し、適切な指紋が提供されたかどうかに応じてデータまたは nil を返します。

// 5. クエリを定義する
NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecAttrAccount: @"My Name1",
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecUseOperationPrompt: @"Please, pass authorisation to enter this area" };

// 6. アイテムを取得する
CFTypeRef queryResult = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &queryResult);

if (status == noErr){
    NSData* resultData = ( __bridge_transfer NSData* )queryResult;
    NSString* password = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", password);
} else {
    NSLog(@"Something went wrong");
}
```

## キーチェーン内の鍵の一過性に関する注釈

macOS や Android とは異なり、iOS は現時点 (iOS 12) ではキーチェーンのアイテムのアクセシビリティの一過性をサポートしていません。キーチェーンに入るときに追加のセキュリティチェックがない場合 (例えば `kSecAccessControlUserPresence` などが設定されている) 、デバイスがアンロックされると、鍵はアクセス可能となります。
