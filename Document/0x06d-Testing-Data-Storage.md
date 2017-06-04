## データストレージのテスト (iOS)

The protection of sensitive data, such as user credentials and private information, is a key focus in mobile security. In this chapter, you will learn about the APIs iOS offers for local data storage, as well as best practices for using those APIs.

Note that "sensitive data" needs to be identified in the context of each specific app. Data classification is described in detail in the chapter "Testing Processes and Techniques".

### ローカルデータストレージのテスト

#### 概要

Common wisdom suggest to save as little sensitive data as possible on permanent local storage. However, in most practical scenarios, a least some types user-related data need to be stored. For example, asking the user to enter a highly complex password every time the app is started isn't a great idea from a usability perspective. As a result, most apps must locally cache some kind of session token. Other types of sensitive data, such as personally identifyable information, might also be saved if the particular scenario calls for it.

Fortunately, Apple's data storage APIs allow developers to make use of the crypto hardware available in every iOS device. Provided that these APIs are used correclty, key data and files can be secured using hardware-backed 256 bit AES encryption.

-- [TODO: Where data shouldn't be saved:] -- 

* CoreData/SQLite データベース
* NSUserDefaults
* プロパティリスト (Plist) ファイル
* プレーンファイル

##### The Keychain

The iOS Keychain is used to securely store short, sensitive bits of data, such as encryption keys and session tokens. It is implemented as an SQLite database that can be accessed only through Keychain APIs. The Keychain database is encrypted using the device Key and the user PIN/password (if one has been set by the user).

By default, each app only can access Keychain created by itself. Access can however be shared between apps signed by the same developer by using the "access groups" feature. Access to the Keychain is managed by the securityd daemon, which grants access based on the app's <code>Keychain-access-groups</code>, <code>application-identifier</code> and <code>application-group</code> entitlements. 

The KeyChain API consists of the following main operations with self-explaining names:

- SecItemAdd
- SecItemUpdate
- SecItemCopyMatching
- SecItemDelete

Keychain data is protected using a class structure similar to the one used for file encryption (see also iOS platfom overview).

Items added with the SecItemAdd call are encoded as a binary plist and encrypted with using an 128 bit AES per-item key. 

Note that larger blobs of data are not to meant to be saved directly in the keychain. That's what the Data Protection API is for (which also makes use of the Keychain).

##### The Data Protection API

App developers can leverage the iOS *Data Protection* APIs to implement fine-grained access control for user data stored in flash memory. The API is built on top of the Secure Enclave, a coprocessor that provides cryptographic operations for Data Protection key management. A device-specific hardware key is embedded into the secure enclave, ensuring the integrity of Data Protection even if the operating system kernel is compromised.

The data protection architecture is based on a hierarchy of keys. The hardware key sits at the top of this hierarchy, and can be used to "unlock" so-called class keys which are associated with different device states (e.g. locked / unlocked).

Every file stored in the iOS file system is encrypted with its own, individual per-file key, which is contained in the file metadata. The metadata is encrypted with the file system key and wrapped with one of the class keys, depending on the protection class selected by the app when creating the the Keychain item.

<img src="Images/Chapters/0x06d/key_hierarchy_apple.jpg" width="500px"/>
*iOS Data Protection Key Hierarchy <sup>[3]</sup>*

Files can be assigned one of four protection classes:

- Complete Protection (NSFileProtectionComplete): This class key is protected with a key derived from the user passcode and the device UID. It is wiped from memory shortly after the device is locked, makimg the data inaccessible until the user unlocks the device.

- Protected Unless Open (NSFileProtectionCompleteUnlessOpen): Behaves similar to Complete Protection, but if the file is opened when unlocked, the app can continue to access the file even if the user locks the device. This is implemented using asymmetric elliptic curve cryptography <sup>[3]</sip>.

- Protected Until First User Authentication (NSFileProtectionCompleteUntilFirstUserAuthentication): The file can be accessed from the moment the user unlocks the device for the first time after booting. It can be accessed even if the user subsequently locks the device.

- No Protection (NSFileProtectionNone): This class key is protected only with the UID and is kept in Effaceable Storage. This protection class exists to enable fast remote wipe: Deleting the class key immediately makes the data inacessible. 

-- [TODO: Finish data protection overview] -- 

#### 静的解析

機密情報をデバイス自体に格納する必要がある場合、キーチェーンなどを使用して iOS デバイスのデバイスを保護するために利用できる関数/API呼び出しがあります。

静的解析の中で機密データがデバイスに永続的に格納されるかどうかを確認する必要があります。機密データを扱う際には以下のフレームワークや関数をチェックする必要があります。

##### CoreData/SQLite データベース

* `Core Data` はアプリケーションのモデルレイヤーオブジェクトを管理するために使用するフレームワークです。オブジェクトライフサイクルおよびオブジェクトグラフ管理(persistenceを含む)に関連する一般的なタスクに一般化および自動化されたソリューションを提供します。Core Data はより低いレベルの sqlite データベースで動作します。

* `sqlite3`: フレームワークセクションの `libsqlite3.dylib` ライブラリはアプリケーションに追加する必要があります。SQLite コマンドに API を提供する C++ ラッパーです。


##### NSUserDefaults

`NSUserDefaults` クラスは default システムと対話するためのプログラム的なインタフェースを提供します。default システムではアプリケーションはユーザーの好みに合わせて動作をカスタマイズできます。NSUserDefaults によって保存されたデータはアプリケーションバンドルから閲覧できます。また plist ファイルにデータを保存しますが、データ量が少なくて済みます。

##### プレーンファイル / Plist ファイル

* `NSData`: NSData は静的データオブジェクトを作成し、NSMutableData は動的データオブジェクトを作成します。NSData と NSMutableData は通常データストレージとして使用されますが、データオブジェクトに含まれるデータをアプリケーション間でコピーや移動ができる、分散オブジェクトアプリケーションでも役に立ちます。
  * NSData オブジェクトの書き込むために使用されるメソッドのオプション: `NSDataWritingWithoutOverwriting, NSDataWritingFileProtectionNone, NSDataWritingFileProtectionComplete, NSDataWritingFileProtectionCompleteUnlessOpen, NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication`
  * NSData クラスの一部としてデータを格納する: `writeToFile`
* ファイルパスを管理する: `NSSearchPathForDirectoriesInDomains, NSTemporaryDirectory`
* `NSFileManager` オブジェクトはファイルシステムの内容を調べて変更することができます。`createFileAtPath` でファイルを作成して書き込みます。


#### 動的解析

資格情報や鍵などの機密情報が安全でない状態で格納されていて iOS のネイティブ関数を利用していないかどうかを特定する方法はアプリのデータディレクトリを解析することです。アプリは特定の機能がユーザーによってトリガーされたときにのみシステム資格情報を格納する可能性があるため、データを解析する前に可能な限り多くのアプリ機能を実行することが重要です。一般的なキーワードとアプリ固有のデータに基づいて、データダンプに対して静的解析を実行します。アプリケーションが iOS デバイスのローカルにデータを格納する方法を特定します。

手順 :

1. 潜在的な機密データを格納する機能をトリガーします。
2. iOS デバイスに接続して次のディレクトリを参照します(これは iOS バージョン 8.0 以降に適用されます)。 `/var/mobile/Containers/Data/Application/$APP_ID/`
3. 格納されたデータに次のような grep コマンドを実行します。 `grep -irn "USERID"`
4. 機密データがプレーンテキストに格納されている場合、このテストは失敗となります。

また、デバッグなどの手動による動的解析を利用して、特定のシステム資格情報がデバイス上でどのように格納および処理されるかを検証することもできます。このアプローチは時間がかかり手動で実行される可能性が高いため、特定のユースケースでのみ実行します。

-- TODO [Add content on Dynamic Testing of "Testing Local Data Storage "] --

#### 改善方法

機密情報(資格情報、鍵、PIIなど)がデバイス上でローカルに必要な場合、車輪を再発明したりデバイス上で暗号化せずに残す代わりに、iOS によって安全にデータを格納するために使用すべきいくつかのベストプラクティスが提供されています。

以下は証明書や鍵や機密情報の安全な保管に一般的に使用されるベストプラクティスのリストです。
* 証明書や鍵などの少量の機密データについては Keychain Services <sup>[1]</sup> を参照ください。キーチェーンデータはファイルデータ保護で使用されているものと同様のクラス構造を使用して保護されます。これらのクラスはファイルデータ保護クラスと同等の振る舞いをしますが、異なる鍵を使用し、異なる名前の API の一部です。デフォルトの振る舞いは `kSecAttrAccessibleWhenUnlocked` です。詳細については、Keychain Item Accessibility <sup>[8]</sup> を参照ください。
* ローカルファイルを暗号化または復号化するために独自実装した暗号化機能は避けるべきです。


#### 参考情報

##### OWASP Mobile Top 10
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.1: "ユーザー資格情報や暗号化鍵などの機密データを格納するために、システムの資格情報保存機能が適切に使用されている。"

##### CWE
* CWE-311 - Missing Encryption of Sensitive Data
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials
* CWE-922 - Insecure Storage of Sensitive Information

##### その他

[1] KeyChain Services - https://developer.apple.com/reference/security/1658642-keychain_services?language=objc
[2] Keychain Services Programming Guide - https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/iPhoneTasks/iPhoneTasks.html
[3] iOS Security Guide - https://www.apple.com/business/docs/iOS_Security_Guide.pdf
[4] File System Basics - https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html
[5] Foundation Functions - https://developer.apple.com/reference/foundation/1613024-foundation_functions
[6] NSFileManager - https://developer.apple.com/reference/foundation/nsfilemanager
[7] NSUserDefaults - https://developer.apple.com/reference/foundation/userdefaults
[8] Keychain Item Accessibility -  https://developer.apple.com/reference/security/1658642-keychain_services/1663541-keychain_item_accessibility_cons


### 機密データに関するテスト(ログ)

#### 概要

モバイルデバイス上にログファイルを作成する理由は正当な理由はたくさんあります。例えば、クラッシュやエラーを追跡するため、オフラインであるときローカルに格納し、再びオンラインになってアプリケーション開発者/企業に送信します。使用統計情報にも使用されます。但し、クレジットカード番号やセッション ID などの機密データを記録すると攻撃者や悪意のあるアプリケーションにデータが公開される可能性があります。
ログファイルはさまざまな方法で作成されます。以下のリストは iOS で利用できるメカニズムを示しています。

* NSLog メソッド
* printf系の関数
* NSAssert系の関数
* マクロ

#### 静的解析

以下のキーワードを使用して定義済み/カスタムのロギングステートメントの使用についてソースコードを確認します。
* 定義済みおよびビルトイン関数の場合：
  * NSLog
  * NSAssert
  * NSCAssert
  * fprintf
* カスタム関数の場合：
  * Logging
  * Logfile


#### 動的解析

ユーザーが機密情報を入力するための入力フィールドがある iOS アプリケーションのページに進みます。ログファイル内の機密データをチェックするには以下の2つの方法があります。

* iOS デバイスに接続して以下のコマンドを実行します。
```
tail -f /var/log/syslog
```

* iOS デバイスを USB 経由で接続して Xcode を起動します。Windows > Devices に移動し、デバイスとそれぞれのアプリケーションを選択します。

入力フィールドのプロンプトを完了した後、上記のコマンドの出力に機密データが表示されている場合、このテストは失敗となります。


#### 改善方法

開発およびデバッグには NSLog を有効にする define を使用し、ソフトウェアを出荷する前に dedine を無効にします。これは適切な PREFIX_HEADER (\*.pch) ファイルに以下のコードを記述することで実行できます。

```C#
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.2: "機密データがアプリケーションログに書き込まれていない。"

##### CWE
* CWE-117: Improper Output Neutralization for Logs
* CWE-532: Information Exposure Through Log Files
* CWE-534: Information Exposure Through Debug Log Files



### 機密データがサードパーティに送信されているかのテスト

#### 概要

さまざまな機能を実装するためにアプリに埋め込むことのできるさまざまなサードパーティサービスが利用できます。これらの機能は追跡サービスによりアプリ内のユーザーの行動を監視したり、バナー広告を販売したり、より良いユーザーエクスペリエンスを作成したりすることができます。これらのサービスとのやりとりは機能を独自に実装して車輪を再発明する複雑性や必要性を抽象化します。

不都合な点としては、開発者がサードパーティライブラリを介してどのようなコードが実行されているかを詳細に把握しておらず、したがって可視性を放棄していることです。したがって、必要以上の情報が送信されないようにし、機密情報が開示されないようにする必要があります。

サードパーティサービスは主に以下の2つの方法で実装されます。
* スタンドアローンのライブラリを使用する。
* 完全な SDK を使用する。

#### 静的解析

サードパーティを通じて提供される API コールや関数は、ベストプラクティスに応じて使用されているかどうかを特定するために、ソースコードレベルでレビューする必要があります。

#### 動的解析

機密情報が埋め込まれている場合には、外部サービスに対するすべてのリクエストを解析する必要があります。動的解析は _Burp Proxy_ や _OWASP ZAP_ を使用して中間者 (MITM) 攻撃を行い、クライアントとサーバー間で交換されるトラフィックを傍受することによって実行します。トラフィックを傍受プロキシにルーティングできるようになると、アプリからのトラフィックを盗聴することが可能になります。アプリを使用する場合、主機能がホストされているサーバーに直接接続していないすべてのリクエストに対し、機密情報がサードパーティに送信されていないかをチェックする必要があります。これには追跡サービスや広告サービスでの PII (個人識別情報) などがあります。

#### 改善方法

サードパーティサービスに送信されるすべてのデータは匿名化する必要があります。そのため PII データは使用できません。また、ユーザーアカウントやセッションにマップできるアプリケーション内の ID などの他のすべてのデータもサードパーティに送信してはいけません。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.3: "機密データはアーキテクチャに必要な部分でない限りサードパーティと共有されていない。"

##### CWE
- CWE-359 "Exposure of Private Information ('Privacy Violation')": [Link to CWE issue]

##### ツール
* OWASP ZAP
* Burp Suite Professional


### 機密データに関するテスト(キーボードキャッシュ)

#### 概要

キーボード入力を簡素化するため、オートコレクト、予測入力、スペルチェックなどを提供します。キーボード入力のほとんどはデフォルトで /private/var/mobile/Library/Keyboard/dynamic-text.dat にキャッシュされます。

この動作は、UITextField, UITextView, UISearchBar で採用されている UITextInputTraits <sup>[1]</sup> プロトコルによって実現されます。キーボードキャッシュは以下のプロパティの影響を受けます。

* `var autocorrectionType: UITextAutocorrectionType` はタイピング中にオートコレクトが有効か無効かを決定します。オートコレクトを有効にすると、テキストオブジェクトは未知語を追跡してより適切な置換候補をユーザーに提案します。ユーザーが明示的にアクションをオーバーライドしない限り、自動的に入力したテキストを置換します。このプロパティのデフォルト値は `UIText​Autocorrection​Type​Default` です。ほとんどの入力メソッドはオートコレクトが有効になります。
* `var secureTextEntry: BOOL` はテキストコピーやテキストキャッシュを無効にするべきかどうかを識別し、UITextField の場合は入力されるテキストを隠します。このプロパティはデフォルトで `NO` に設定されています。

#### 静的解析


* 提供されたソースコードを検索して、以下と同様の実装を探します。

  ```
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
  ```

* Interface Builder で xib と storyboard ファイルを開き、適切なオブジェクトの Attributes Inspector の Secure Text Entry and Correction の状態を確認します。


#### 動的解析

1. iOS デバイスのキーボードキャッシュをリセットします。設定 > 一般 > リセット > キーボードの変換学習をリセット

2. アプリケーションの機能を使用していきます。ユーザーが機密データを入力できる機能を特定します。

3. 以下のディレクトリにあるキーボードキャッシュファイル dynamic-text.dat をダンプします(8.0 未満の iOS では異なる場合があります)。
/private/var/mobile/Library/Keyboard/

4. ユーザー名、パスワード、電子メールアドレス、クレジットカード番号などの機密データを探します。機密データがキーボードキャッシュファイルから取得できる場合、このテストは失敗となります。

#### 改善方法

アプリケーションはテキストフィールドに入力された機密情報を含むデータをキャッシュしないことを保証する必要があります。これは目的の UITextFields, UITextViews, UISearchBars で `textObject.autocorrectionType = UITextAutocorrectionTypeNo` ディレクティブを使用して、プログラムで機能を無効にすることで実現できます。PIN やパスワードなどのマスクする必要のあるデータについては、`textObject.secureTextEntry` に `YES` を設定します。

```#ObjC
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.4: "機密データを処理するテキスト入力では、キーボードキャッシュが無効にされている。"

##### CWE
- CWE-524: Information Exposure Through Caching

#### その他
[1] UIText​Input​Traits protocol - https://developer.apple.com/reference/uikit/uitextinputtraits



### 機密データに関するテスト(クリップボード)

#### 概要

入力フィールドにデータを入力する際に、クリップボードを使用してデータをコピーできます。クリップボードはシステム全体でアクセス可能であり、そのためアプリ間で共有されます。この機能は機密データを取得するために悪意のあるアプリによって悪用されます。

#### 静的解析

提供されたソースコードを検索して、`UITextField` のサブクラス実装を探します。

```
@interface name_of_sub_class : UITextField
action == @select(cut:)
action == @select(copy:)
```

#### 動的解析

ユーザーにユーザー名、パスワード、クレジットカード番号などの機密情報を指示する入力フィールドがあるアプリケーションのビューに進みます。何かしらの値を入力して入力フィールドをダブルタップします。「選択」「全選択」「ペースト」オプションが表示されている場合、「選択」または「全選択」オプションをタップすると、「カット」「コピー」「ペースト」が使えます。ペーストにより値を取得することができるため、機密入力フィールドでは「カット」および「コピー」オプションは無効にする必要があります。機密入力フィールドで内容を「カット」または「コピー」することができる場合、このテストは失敗となります。


#### 改善方法

以下の改善方法が考えられます <sup>[1]</sup>。

```#ObjC
@interface NoSelectTextField : UITextField

@end

@implementation NoSelectTextField

- (BOOL)canPerformAction:(SEL)action withSender:(id)sender {
    if (action == @selector(paste:) ||
        action == @selector(cut:) ||
        action == @selector(copy:) ||
        action == @selector(select:) ||
        action == @selector(selectAll:) ||
        action == @selector(delete:) ||
        action == @selector(makeTextWritingDirectionLeftToRight:) ||
        action == @selector(makeTextWritingDirectionRightToLeft:) ||
        action == @selector(toggleBoldface:) ||
        action == @selector(toggleItalics:) ||
        action == @selector(toggleUnderline:)
        ) {
            return NO;
    }
    return [super canPerformAction:action withSender:sender];
}

@end
```
ペーストボードをクリアするには <sup>[2]</sup>。

```
UIPasteboard *pb = [UIPasteboard generalPasteboard];
[pb setValue:@"" forPasteboardType:UIPasteboardNameGeneral];
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.5: "機密データを含む可能性があるテキストフィールドでは、クリップボードが無効化されている。"

##### CWE
- CWE-200: Information Exposure

#### Info
[1] Disable clipboard on iOS - http://stackoverflow.com/questions/1426731/how-disable-copy-cut-select-select-all-in-uitextview
[2] UIPasteboardNameGeneral - https://developer.apple.com/reference/uikit/uipasteboardnamegeneral?language=objc


### 機密データがIPCメカニズムを介して漏洩しているかのテスト

#### 概要

-- TODO [Add content on overview of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 静的解析

-- TODO [Add content on white-box testing of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 動的解析

-- TODO [Add content on black-box testing of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 改善方法

-- TODO [Add remediation on "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.6: "機密データがIPCメカニズムを介して公開されていない。"

##### CWE
- CWE

#### その他
-- TODO --


### ユーザーインタフェースを介しての機密データ漏洩に関するテスト

##### 概要

-- TODO [Add content on overview for "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 静的解析

-- TODO [Add content on white-box testing of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 動的解析

-- TODO [Add content on black-box testing of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 改善方法

-- TODO [Add remediation of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.7: "パスワードやピンなどの機密データは、ユーザーインタフェースを介して公開されていない。"

##### CWE
- CWE

#### その他
-- TODO --


### 機密データに関するテスト(バックアップ)

#### 概要

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places. When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information, PII).

Consequences for disclosing sensitive information can be various, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify this information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from apps that have a payment option in order to attack and abuse it.

Storing data is essential for many mobile applications, for example in order to keep track of user settings or data a user has keyed in that needs to be stored locally or offline. Data can be stored persistently in various ways. The following list shows those mechanisms that are available on the iOS platform<sup>[6]</sup>:

* AppName.app
  * The app’s bundle, contains the app and all of its resources
  * Visible to users but users cannot write to this directory
  * Contents in this directory are not backed up
* Documents/
  * Use this directory to store user-generated content
  * Visible to users and users can write to this directory
  * Contents in this directory are being backed up
  * App can disable paths by setting `NSURLIsExcludedFromBackupKey`
* Library/
  * This is the top-level directory for any files that are not user data files
  * iOS apps commonly use the `Application Support` and `Caches` subdirectories, but you can create custom subdirectories
* Library/Caches/
  * Semi-persistent cached files
  * Not visible to users and users cannot write to this directory
  * Contents in this directory are not backed up
  * OS may delete the files automatically when app is not running (e.g. storage space running low)
* Library/Application Support/
  * Persistent files necessary to run the app
  * Not visible to users and users cannot write to this directory
  * Contents in this directory are being backed up
  * App can disable paths by setting `NSURLIsExcludedFromBackupKey`
* tmp/ 
  * Use this directory to write temporary files that do not need to persist between launches of your app
  * Non-persistent cached files
  * Not visible to the user
  * Not backed up
  * OS may delete the files automatically when app is not running (e.g. storage space running low)

#### 静的解析

Review the iOS mobile application source code to see if there is any usage of the `NSURLIsExcludedFromBackupKey`<sup>[1]</sup> or `kCFURLIsExcludedFromBackupKey`<sup>[2]</sup> file system properties to exclude files and directories from backups. Apps that need to exclude a large number of files can exclude them by creating their own sub-directory and marking that directory as excluded. Apps should create their own directories for exclusion, rather than excluding the system defined directories. 

Either of these APIs is preferred over the older, deprecated approach of directly setting an extended attribute. All apps running on iOS 5.1 and later should use these APIs to exclude data from backups. 

The following is a sample code for excluding a file from backup on iOS 5.1 and later (Objective-C)<sup>[3]</sup>:

```#ObjC
- (BOOL)addSkipBackupAttributeToItemAtPath:(NSString *) filePathString
{
    NSURL* URL= [NSURL fileURLWithPath: filePathString];
    assert([[NSFileManager defaultManager] fileExistsAtPath: [URL path]]);
 
    NSError *error = nil;
    BOOL success = [URL setResourceValue: [NSNumber numberWithBool: YES]
                                  forKey: NSURLIsExcludedFromBackupKey error: &error];
    if(!success){
        NSLog(@"Error excluding %@ from backup %@", [URL lastPathComponent], error);
    }
    return success;
}
```

The following is a sample code for excluding a file from backup on iOS 5.1 and later (Swift)<sup>[3]</sup>:

```
 func addSkipBackupAttributeToItemAtURL(filePath:String) -> Bool
    {
        let URL:NSURL = NSURL.fileURLWithPath(filePath)
 
        assert(NSFileManager.defaultManager().fileExistsAtPath(filePath), "File \(filePath) does not exist")
 
        var success: Bool
        do {
            try URL.setResourceValue(true, forKey:NSURLIsExcludedFromBackupKey)
            success = true
        } catch let error as NSError {
            success = false
            print("Error excluding \(URL.lastPathComponent) from backup \(error)");
        }
 
        return success
    }
```

If your app must support iOS 5.0.1, you can use the following method to set the "do not back up" extended attribute. Whenever you create a file or folder that should not be backed up, write the data to the file and then call the following method, passing in a URL to the file<sup>[3]</sup>:

```
#import <sys/xattr.h>
- (BOOL)addSkipBackupAttributeToItemAtPath:(NSString *) filePathString
{
    assert([[NSFileManager defaultManager] fileExistsAtPath: filePathString]);
 
    const char* filePath = [filePathString fileSystemRepresentation];
 
    const char* attrName = "com.apple.MobileBackup";
    u_int8_t attrValue = 1;
 
    int result = setxattr(filePath, attrName, &attrValue, sizeof(attrValue), 0, 0);
    return result == 0;
}
```

Lastly, it is not possible to exclude data from backups on iOS 5.0. If your app must support iOS 5.0, then you will need to store your app data in `Caches` to avoid having the data being backed up. iOS will delete your files from the Caches directory when necessary, so your app will need to degrade gracefully if its data files are deleted.

#### 動的解析

After the App data has been backed up, review the data content of the backup files and folders. Specifically, the following directories should be reviewed to check if it contains any sensitive data: 

* Documents/
* Library/Caches/
* Library/Application Support/
* tmp/

Refer to the Overview of this section to read up more on the purpose of each of the mentioned directories and the type of information they stores.  

#### 改善方法

In performing an iTunes backup of a device on which a particular mobile application has been installed, the backup will include all subdirectories (except for the `Library/Caches/` subdirectory) and files contained within that app's private directory on the device's file system<sup>[4]</sup>. 

As such, avoid storing any sensitive data in plaintext within any of the files or folders within the app's private directory or subdirectories.

While all the files in `Documents/` and `Library/Application Support/` are always being backed up by default, it is possible to exclude files from the backup by calling `[NSURL setResourceValue:forKey:error:]` using the `NSURLIsExcludedFromBackupKey` key<sup>[5]</sup>. 

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.8: "機密データがモバイルオペレーティングシステムにより生成されるバックアップに含まれていない。"

##### CWE
- CWE-200: Information Exposure
- CWE-538: File and Directory Information Exposure

#### その他
- [1] NSURLIsExcludedFromBackupKey - https://developer.apple.com/reference/foundation/nsurl#//apple_ref/c/data/NSURLIsExcludedFromBackupKey
- [2] kCFURLIsExcludedFromBackupKey - https://developer.apple.com/reference/corefoundation/cfurl-rd7#//apple_ref/c/data/kCFURLIsExcludedFromBackupKey
- [3] How do I prevent files from being backed up to iCloud and iTunes? - https://developer.apple.com/library/content/qa/qa1719/index.html
- [4] Directories of an iOS App - https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12
- [5] Where You Should Put Your App’s Files - https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28
- [6] - iOS File System Overview https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28


### 自動生成されるスクリーンショットの機密情報に関するテスト

#### 概要

製造業者はアプリケーションへの出入りの際に美的で魅力的な効果をデバイスユーザーに提供したいため、アプリケーションがバックグラウンドになるとスクリーンショットを保存するというコンセプトが導入されました。この機能は機密情報を含むスクリーンショット(電子メールや企業文書のスクリーンショットなど)がローカルストレージに書き込まれるため、アプリケーションにセキュリティリスクを引き起こす可能性があります。脱獄されたデバイス上の不正なアプリケーションやデバイスを盗む何者かによって取得される可能性があります。

#### 静的解析

ソースコードを解析する中で、機密データが含まれるフィールドや画面を探します。アプリケーションがバックグラウンドされる前に画面をサニタイズするかどうかを特定します。

#### 動的解析

アプリケーション上でユーザー名、電子メールアドレス、アカウント詳細などの機密情報を表示するページに進みます。iOS デバイスのホームボタンを押して、アプリケーションをバックグラウンドにします。iOS デバイスに接続して以下のディレクトリに進みます(8.0 未満の iOS では異なる場合があります)。

`/var/mobile/Containers/Data/Application/$APP_ID/Library/Caches/Snapshots/`

アプリケーションがスクリーンショットとして機密情報ページをキャッシュしている場合、このテストは失敗となります。

アプリケーションがバックグラウンドに入るたびにキャッシュされるデフォルトのスクリーンショットを持つことを強く推奨します。


#### 改善方法

デフォルトのスクリーンショットを設定する改善方法が考えられます。

```
@property (UIImageView *)backgroundImage;
 
- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    [self.window addSubview:myBanner];
}
```

これによりアプリケーションがバックグラウンドされるときはいつでもバックグラウンドイメージに "overlayImage.png" が設定されます。"overlayImage.png" は常に現在の view を上書きするため、機密データの漏洩を防ぎます。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.9: "バックグラウンド時にアプリはビューから機密データを削除している。"

##### CWE
- CWE

#### Info
-- TODO [Add references for "Testing For Sensitive Information in Auto-Generated Screenshots" ] --



### メモリ内の機密データのテスト

-- TODO [Add content for "Testing for Sensitive Data in Memory"] --

#### 概要

-- TODO

#### 静的解析

-- TODO

#### 動的解析

-- TODO

#### 改善方法

-- TODO

#### 参考情報

##### OWASP MASVS
- V2.10: "アプリは必要以上に長くメモリ内に機密データを保持せず、使用後は明示的にメモリがクリアされている。"

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用

##### CWE
- CWE: -- TODO [Add link to CWE issue] --

#### その他
-- TODO



### デバイスアクセスセキュリティポリシーのテスト

#### 概要

-- TODO [Add content for overview of "Testing the Device-Access-Security Policy"] --

#### 静的解析

-- TODO [Add content for static analysis of "Testing the Device-Access-Security Policy"] --

#### 動的解析

-- TODO [Add content for dynamic analysis of "Testing the Device-Access-Security Policy"] --

#### 改善方法

-- TODO [Add remediation of "Testing the Device-Access-Security Policy"] --

#### 参考情報

##### OWASP MASVS
- V2.11: "アプリは最低限のデバイスアクセスセキュリティポリシーを適用しており、ユーザーにデバイスパスコードを設定することなどを必要としている。"

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用

##### CWE
- CWE: -- TODO [Add link to CWE issue] --

#### その他
-- TODO


### ユーザー通知コントロールの検証

#### 概要

ユーザーに通知することはモバイルアプリの使用における重要な要素です。多くのセキュリティコントロールがすでに導入されていたとしても、ユーザーによって迂回や誤用される可能性があります。

以下のリストは最初にアプリを開いて使用する際の仮想的な警告またはアドバイスを示しています。
* アプリは初回起動後にローカルおよびリモートに格納されているデータのリストを表示します。情報が広い範囲におよぶ可能性があるため、外部リソースへリンクすることも可能です。
* アプリ内で新規ユーザーアカウントを作成する場合、提供されたパスワードがセキュアでありベストプラクティスパスワードポリシーに当てはまるかどうかをユーザーに表示します。
* ユーザーがルート化デバイスにアプリをインストールする場合、危険であり、OS レベルのセキュリティコントロールを無効にし、マルウェアに感染されやすくなるという警告を表示します。詳細は OMTG-DATAST-011 も参照ください。
* ユーザーが古いバージョンの Android にアプリをインストールする場合、警告を表示します。詳細は OMTG-DATAST-010 も参照ください。

-- TODO [What else can be a warning on iOS?] --

#### 静的解析

-- TODO [Add content for static analysis of "Verifying User Education Controls"] --

#### 動的解析

アプリをインストールした後や使用中に、ユーザーに啓蒙目的の警告が表示されているかどうかを確認する必要があります。

-- TODO [Further develop content of dynamic analysis of "Verifying User Education Controls"] --

#### 改善方法

概要セクションに記載されているキーポイントに対処する警告を実装する必要があります。

-- TODO [Further develop remediation of "Verifying User Education Controls"] --

#### 参考情報

-- TODO [Add references for "Verifying User Education Controls"] --

##### OWASP MASVS

- V2.12: "アプリは処理される個人識別情報の種類、およびユーザーがアプリを使用する際に従うべきセキュリティのベストプラクティスについて通知している。"

##### OWASP Mobile Top 10 2016

* M1 - 不適切なプラットフォームの利用

##### CWE
- CWE: -- TODO [Add link to CWE issue for "Verifying User Education Controls"] --

#### その他
-- TODO
