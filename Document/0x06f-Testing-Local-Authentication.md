## iOS のローカル認証

ローカル認証では、アプリはデバイス上でローカルに保存された資格情報に対してユーザーを認証します。言い換えると、ユーザーはローカルデータを参照することにより検証される PIN、パスワード、顔認識、指紋を提供することで、アプリや機能の何かしらの内部層を「アンロック」します。一般的に、これはユーザーがより便利にリモートサービスでの既存のセッションを再開するため、またはある重要な機能を保護するためのステップアップ認証の手段として行われます。

モバイルアプリの認証アーキテクチャの章で前述しているように、テスト技術者はローカル認証が常にリモートエンドポイントで実行されることや暗号プリミティブに基づいている必要があることに注意します。認証プロセスからデータが返らない場合、攻撃者は簡単にローカル認証をバイパスできます。

### ローカル認証のテスト

iOS にはアプリにローカル認証を統合するためのさまざまな方法が用意されています。[Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") では開発者がユーザーへの認証ダイアログを拡張するための一連の API が提供されています。リモートサービスに接続するコンテキストでは、ローカル認証を実装するに [キーチェーン](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Introduction into the Keychain") を利用することが可能であり (および推奨され) ます。

iOS での指紋認証は *Touch ID* として知られています。指紋 ID センサーは [SecureEnclave security coprocessor](http://mista.nu/research/sep-paper.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") により操作され、指紋データをシステムの他の部分に開示することはありません。Touch ID の次に、Apple は顔認識に基づく認証を可能にする *Face ID* を導入しました。いずれもアプリケーションレベルで、データを格納し、データを格納する実際の手法として、似たような API を使用します (例えば、顔データと指紋関連データが異なります) 。

開発者には Touch ID/FaceID 認証を組み込むために二つの選択肢があります。

- `LocalAuthentication.framework` は上位レベルの API であり、Touch ID 経由でユーザーを認証するために使用できます。アプリは登録された指紋に関連付けられたデータにアクセスすることはできません。認証が成功したかどうかだけが通知されます。
- `Security.framework` は下位レベルの API であり、[Keychain Services](https://developer.apple.com/documentation/security/keychain_services "Keychain Services") にアクセスします。アプリが生体認証である機密データを保護する必要がある場合、アクセス制御はシステムレベルで管理され、簡単にはバイパスできないため、これはセキュアな選択肢です。`Security.framework` には C API がありますが、いくつかの [オープンソースラッパーを利用](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The Keychain and Touch ID") して、キーチェーンへのアクセスを NSUserDefaults のように簡単に行えます。`Security.framework` は `LocalAuthentication.framework` の基礎にあります。Apple は可能であれば上位レベル API をデフォルトとすることを推奨しています。

`LocalAuthentication.framework` または `Security.framework` のいずれかを使用すると、ブール値を返すだけで処理を続けるデータがないため、攻撃者がバイパスできるコントロールになることに注意します。詳細については [Don't touch me that way, by David Lidner et al](https://www.youtube.com/watch?v=XhXIHVGCFFM) を参照してください。

##### ローカル認証フレームワーク

ローカル認証フレームワークはユーザーからのパスフレーズまたは Touch ID 認証を要求する機能を提供します。開発者は `LAContext` クラスの関数 `evaluatePolicy` を利用して、認証プロンプトを表示および利用できます。

二つの利用可能なポリシーでは受け入れ可能な認証形式を定義します。

- `deviceOwnerAuthentication`(Swift) または `LAPolicyDeviceOwnerAuthentication`(Objective-C): 利用可能な場合、ユーザーは Touch ID 認証を実行するよう促されます。Touch ID が有効ではない場合には、デバイスパスコードを代わりに要求されます。デバイスパスコードが有効ではない場合、ポリシー評価は失敗します。

- `deviceOwnerAuthenticationWithBiometrics` (Swift) または `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C): 認証はユーザーが Touch ID を促される生体認証に制限されます。

`evaluatePolicy` 関数はユーザーが認証に成功したかどうかを示すブール値を返します。

Apple Developer ウェブサイトでは [Swift](https://developer.apple.com/documentation/localauthentication) と [Objective-C](https://developer.apple.com/documentation/localauthentication?language=objc) の両方のコードサンプルを提供しています。Swift での典型的な実装は以下のようになります。

```swift
let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
	// ポリシーを評価できなかった。error を見て、適切なメッセージをユーザーに提示する
}

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please, pass authorization to enter this area") { success, evaluationError in
	guard success else {
		// ユーザーが正常に認証されなかった。evaluationError を見て、適切な処置を講じる。
	}

	// ユーザーが正常に認証された。適切な処理を講じる。
}
```
*ローカル認証フレームワークを使用した Swift での Touch ID 認証 (Apple の公式コードサンプル)*

##### ローカル認証にキーチェーンサービスを使用する

ローカル認証を実装するには iOS Keychain API を使用できます (そして、使用すべきです) 。このプロセスでは、アプリは秘密の認証トークンかキーチェーンでユーザーを識別する別の秘密データを格納します。リモートサービスを認証するには、ユーザーは秘密のデータを取得するためにパスフレーズまたは指紋を使用してキーチェーンをアンロックする必要があります。

キーチェーンは特別な `SecAccessControl` 属性でアイテムを保存することができます。これはユーザーが Touch ID 認証 (またはパスコード、属性パラメータによりそのようなフォールバックが許可されている場合) をパスした後でのみ、キーチェーンからアイテムへのアクセスを許可します。

以下の例では、文字列 "test_strong_password" をキーチェーンに保存します。この文字列は、パスコードが設定されている間 (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` パラメータ)、かつ現在登録されている指のみでの Touch ID 認証後 (`.touchIDCurrentSet パラメータ`) に、現在のデバイス上でのみアクセス可能です。

**Swift**

```swift

// 1. 認証設定を表す AccessControl オブジェクトを作成する

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	.touchIDCurrentSet,
	&error) else {
    // failed to create AccessControl object
}

// 2. キーチェーンサービスクエリを定義する。kSecAttrAccessControl は kSecAttrAccessible 属性と相互排他的であることに注意する

var query: Dictionary<String, Any> = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. アイテムを保存する

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
	// 正常に保存された
} else {
	// 保存中にエラーが発生
}
```

**Objective-C**

```objc

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
		// 正常に保存された
	} else {
		// 保存中にエラーが発生
	}
```

これで保存したアイテムをキーチェーンからリクエストできます。キーチェーンサービスはユーザーに認証ダイアログを表示し、適切な指紋が提供されたかどうかに応じてデータまたは nil を返します。

**Swift**

```swift
// 1. クエリを定義する
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 2. アイテムを取得する
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

**Objective-C**

```objc
// 1. クエリを定義する
NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecAttrAccount: @"My Name1",
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecUseOperationPrompt: @"Please, pass authorisation to enter this area" };

// 2. アイテムを取得する
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

アプリ内のフレームワークの使用はアプリバイナリの共有ダイナミックライブラリのリストを解析することによっても検出できます。これは otool を使うことにより行えます。

```shell
$ otool -L <AppName>.app/<AppName>
```

`LocalAuthentication.framework` がアプリで使用されている場合、その出力には以下の行が両方含まれます (`LocalAuthentication.framework` は内部で `Security.framework` を使用します) 。

```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

`Security.framework` が使用されている場合、二番目のものだけが表示されます。

#### 静的解析

ローカル認証フレームワークはイベントベースのプロシージャであり、唯一の認証方法ではないことに注意します。このタイプの認証はユーザーインタフェースレベルで有効ですが、パッチ適用や計装で容易にバイパスされます。

- 支払いトランザクションをトリガーするユーザーの再認証などの機密プロセスが、キーチェーンサービスメソッドを使用して保護されていることを検証します。
- `SecAccessControlCreateWithFlags` メソッドがコールされる際に、`kSecAccessControlTouchIDAny` または `kSecAccessControlTouchIDCurrentSet` フラグが設定され、`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` 保護クラスが設定されていることを検証します。代わりに、フォールバックとしてパスコードを使用できるようにしたい場合に `kSecAccessControlUserPresence` がフラグとして使用できることに注意します。最後に、`kSecAccessControlTouchIDCurrentSet` が設定されている場合、デバイスに登録されている指紋を変更すると、そのフラグで保護されているエントリが無効になることに注意します。

#### 動的解析

[Swizzler2](https://github.com/vtky/Swizzler2 "Swizzler2") や [Needle](https://github.com/mwrlabs/needle "Needle") などの脱獄済みデバイス用ツールを使用して LocalAuthentication をバイパスできます。いずれのツールも Frida を使用して `evaluatePolicy` 関数を計装し、認証が成功しなくても `True` を返すようにします。Swizzler2 でこの機能を有効にするには以下の手順に従います。

- Settings->Swizzler
- "Inject Swizzler into Apps" を有効にします
- "Log Everything to Syslog" を有効にします
- "Log Everything to File" を有効にします
- サブメニュー "iOS Frameworks" に入ります
- "LocalAuthentication" を有効にします
- サブメニュー "Select Target Apps" に入ります
- ターゲットアプリを有効にします
- アプリを閉じて再度起動します
- Touch ID プロンプトが表示されたら "cancel" をクリックします
- Touch ID を必要とせずにアプリケーションフローが継続する場合、そのバイパスは機能しています。

Needle を使用している場合には、"hooking/frida/script_touch-id-bypass" モジュールを実行してプロンプトに従います。これによりアプリケーションを開始して `evaluatePolicy` 関数を計装します。Touch ID で認証が求められた場合、cancel をタップします。アプリケーションフローが継続する場合、Touch ID のバイパスに成功しています。frida の代わりに cycript を使用する同様のモジュール (hooking/cycript/cycript_touchid) も Needle で利用できます。

あるいは、[objection to bypass Touch ID](https://github.com/sensepost/objection/wiki/Understanding-the-TouchID-Bypass "Understanding the TouchID Bypass") (これは非脱獄済みデバイス上でも機能します) を使用したり、アプリにパッチを当てたり、Cycript や同様のツールを使用してプロセスを計装することもできます。

Needle を使用して iOS プラットフォームの非セキュアな生体認証をバイパスできます。Needle は frida を利用して、`LocalAuthentication.framework` API を使用して開発されたログインフォームをバイパスします。以下のモジュールを使用して、非セキュアな生体認証をテストできます。

```
[needle][container] > use hooking/frida/script_touch-id-bypass
[needle][script_touch-id-bypass] > run
```

脆弱である場合、モジュールは自動的にログインフォームをバイパスします。

### キーチェーン内の鍵の一過性に関する注釈
MacOSX や Android とは異なり、iOS は現時点 (iOS 12) ではキーチェーンのエントリのアクセシビリティの一過性をサポートしていません。キーチェーンに入るときに追加のセキュリティチェックがない場合 (例えば `kSecAccessControlUserPresence` などが設定されている) 、デバイスがアンロックされると、鍵はアクセス可能となります。


### 参考情報

#### OWASP Mobile Top 10 2016

- M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M4-Insecure_Authentication.html

#### OWASP MASVS

- V4.8: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"
- v2.11: "アプリは最低限のデバイスアクセスセキュリティポリシーを適用しており、ユーザーにデバイスパスコードを設定することなどを必要としている。"

#### CWE

- CWE-287 - Improper Authentication
