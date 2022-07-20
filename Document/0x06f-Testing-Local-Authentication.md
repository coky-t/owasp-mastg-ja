# iOS のローカル認証

ローカル認証では、アプリはデバイス上でローカルに保存された資格情報に対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、または顔や指紋などの生体特性を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、これはユーザーがより便利にリモートサービスでの既存のセッションを再開するため、またはある重要な機能を保護するためのステップアップ認証の手段として行われます。

"[モバイルアプリの認証アーキテクチャ](0x04e-Testing-Authentication-and-Session-Management.md)" の章で前述しているように、テスト技術者はローカル認証が常にリモートエンドポイントで実行されることや暗号プリミティブに基づいている必要があることに注意します。認証プロセスからデータが返らない場合、攻撃者は簡単にローカル認証をバイパスできます。

## ローカル認証のテスト (MSTG-AUTH-8 および MSTG-STORAGE-11)

iOS にはアプリにローカル認証を統合するためのさまざまな方法が用意されています。[Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") では開発者がユーザーへの認証ダイアログを拡張するための一連の API が提供されています。リモートサービスに接続するコンテキストでは、ローカル認証を実装するに [キーチェーン](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Keychain Services") を利用することが可能であり (および推奨され) ます。

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

```default
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

- _ローカル認証フレームワークを使用した Swift での Touch ID 認証 (Apple の公式コードサンプル)_

### ローカル認証にキーチェーンサービスを使用する

ローカル認証を実装するには iOS keychain API を使用できます (そして、使用すべきです) 。このプロセスでは、アプリは秘密の認証トークンかキーチェーンでユーザーを識別する別の秘密データを格納します。リモートサービスを認証するには、ユーザーは秘密のデータを取得するためにパスフレーズまたは指紋を使用してキーチェーンをアンロックする必要があります。

キーチェーンは特別な `SecAccessControl` 属性でアイテムを保存することができます。これはユーザーが Touch ID 認証 (またはパスコード、属性パラメータによりそのようなフォールバックが許可されている場合) をパスした後でのみ、キーチェーンからアイテムへのアクセスを許可します。

以下の例では、文字列 "test_strong_password" をキーチェーンに保存します。この文字列は、パスコードが設定されている間 (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` パラメータ)、かつ現在登録されている指のみでの Touch ID 認証後 (`SecAccessControlCreateFlags.biometryCurrentSet パラメータ`) に、現在のデバイス上でのみアクセス可能です。

#### Swift

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

#### Objective-C

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

アプリ内のフレームワークの使用はアプリバイナリの共有ダイナミックライブラリのリストを解析することによっても検出できます。これは [otool](0x08a-Testing-Tools.md#otool) を使うことにより行えます。

```bash
otool -L <AppName>.app/<AppName>
```

`LocalAuthentication.framework` がアプリで使用されている場合、その出力には以下の行が両方含まれます (`LocalAuthentication.framework` は内部で `Security.framework` を使用します) 。

```bash
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

`Security.framework` が使用されている場合、二番目のものだけが表示されます。

### 静的解析

ローカル認証フレームワークはイベントベースのプロシージャであり、唯一の認証方法ではないことに注意します。このタイプの認証はユーザーインタフェースレベルで有効ですが、パッチ適用や計装で容易にバイパスされます。したがって、キーチェーンサービスメソッドを使用することをお勧めします。つまり、以下を行う必要があります。

- 支払いトランザクションを実行するユーザーの再認証などの機密プロセスが、キーチェーンサービスメソッドを使用して保護されていることを検証します。
- キーチェーンアイテムのデータがユーザーの認証によってのみロック解除できるようにするために、アクセス制御フラグがキーチェーンアイテムに設定されていることを検証します。これには以下のフラグのいずれかを使用できます。
  - `kSecAccessControlBiometryCurrentSet` (iOS 11.3 より前では `kSecAccessControlTouchIDCurrentSet`) 。これによりユーザーがキーチェーンアイテムのデータにアクセスする前に、ユーザーが生体情報 (Face ID や Touch ID など) で認証する必要があることを確実にします。ユーザーがデバイスに指紋や顔の表現を追加すると、キーチェーンのエントリが自動的に無効になります。これによりアイテムがキーチェーンに追加されたときに登録されていたユーザーのみがキーチェーンアイテムのロックを解除できるようになります。
  - `kSecAccessControlBiometryAny` (iOS 11.3 より前では `kSecAccessControlTouchIDAny`) 。これによりユーザーがキーチェーンアイテムのデータにアクセスする前に、ユーザーが生体情報 (Face ID や Touch ID など) で認証する必要があることを確実にします。キーチェーンは新しい指紋や顔の表現を (再) 登録しても存続します。ユーザーの指紋が変化している場合、これは非常に便利です。但し、指紋や顔の表現を何らかの方法でデバイスに登録できる攻撃者は、これらのエントリにもアクセスできることも意味します。
  - `kSecAccessControlUserPresence` を代替として使用できます。これにより生体認証が機能しない場合に、ユーザーはパスコードを介して認証できます。Touch ID や Face ID サービスをバイパスするよりも、ショルダーサーフィンによって誰かのパスコードエントリを盗むほうがはるかに簡単であるため、`kSecAccessControlBiometryAny` よりも脆弱であると考えられます。
- 生体情報を使用できるようにするために、`SecAccessControlCreateWithFlags` メソッドがコールされたときに `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` または `kSecAttrAccessibleWhenPasscodeSet` 保護クラスが設定されていることを検証します。`...ThisDeviceOnly` バリアントはキーチェーンアイテムが他の iOS デバイスと同期されないようにすることに注意します。

> 注意、データ保護クラスはデータをセキュアにするために使用されるアクセス方法を指定します。
各クラスはいつデータがアクセス可能となるかを決定するために異なるポリシーを使用します。

### 動的解析

[Objection Biometrics Bypass](https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass "Understanding the iOS Biometrics Bypass") を使用して LocalAuthentication をバイパスできます。 Objection は Frida を使用して `evaluatePolicy` 関数を計装し、認証が成功しなかった場合でも `True` を返します。 `ios ui biometrics_bypass` コマンドを使用して、セキュアではない生体認証をバイパスします。Objection はジョブを登録して `evaluatePolicy` の結果を置き換えます。 Swift と Objective-C の両方の実装で機能します。

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios ui biometrics_bypass
(agent) Registering job 3mhtws9x47q. Type: ios-biometrics-disable
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # (agent) [3mhtws9x47q] Localized Reason for auth requirement: Please authenticate yourself
(agent) [3mhtws9x47q] OS authentication response: false
(agent) [3mhtws9x47q] Marking OS response as True instead
(agent) [3mhtws9x47q] Biometrics bypass hook complete
```

脆弱な場合、モジュールはログインフォームを自動的にバイパスします。

## キーチェーン内の鍵の一過性に関する注釈

macOS や Android とは異なり、iOS は現時点 (iOS 12) ではキーチェーンのアイテムのアクセシビリティの一過性をサポートしていません。キーチェーンに入るときに追加のセキュリティチェックがない場合 (例えば `kSecAccessControlUserPresence` などが設定されている) 、デバイスがアンロックされると、鍵はアクセス可能となります。

## 参考情報

### OWASP MASVS

- MSTG-AUTH-8: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"
- MSTG-STORAGE-11: "アプリは最低限のデバイスアクセスセキュリティポリシーを適用しており、ユーザーにデバイスパスコードを設定することなどを必要としている。"
