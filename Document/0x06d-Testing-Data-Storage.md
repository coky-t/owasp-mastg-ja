## データストレージのテスト (iOS)

ユーザー資格情報や個人情報などの機密データを保護することはモバイルセキュリティの重要な焦点です。この章では、iOS がローカルデータストレージ用に提供する API およびそれらの API を使用するためのベストプラクティスについて学びます。

「機密データ」は特定のアプリごとのコンテキストで識別する必要があることに注意します。データ分類については「モバイルアプリセキュリティのベストプラクティスと落とし穴」の章で詳しく説明しています。

### ローカルデータストレージのテスト

#### 概要

このガイドでは何度も述べているように、できるだけ機密性の低いデータを永続的なローカルストレージに保存すべきです。しかし、ほとんどの実際のシナリオでは、少なくともいくつかのタイプのユーザー関連データを格納する必要があります。幸運にも、iOS はセキュアなストレージ API を提供しています。これにより開発者はすべての iOS デバイスで利用可能な暗号ハードウェアを使用できます。提供されるこれらの API が正しく使用されれば、ハードウェア支援の 256 ビット AES 暗号化を使用して、重要なデータやファイルを保護することができます。

##### Data Protection API

アプリ開発者は iOS *Data Protection* API を活用して、フラッシュメモリに格納されたユーザーデータに対してきめ細かなアクセス制御を実装することができます。この API は Secure Enclave 上に構築されています。Secure Enclave は Data Protection の鍵管理に対して暗号操作を提供するコプロセッサです。デバイス固有のハードウェアキー - デバイス UID - が Secure Enclave に組み込まれているため、オペレーティングシステムカーネルが侵害された場合でも Data Protection の完全性が保証されます。

データ保護アーキテクチャは鍵の階層に基づいています。UID とユーザーパスコードキーは PBKDF2 アルゴリズムを使用してユーザーのパスフレーズから導出され、この階層の最上位に位置します。ともに、それらはさまざまなデバイス状態 (デバイスのロック、アンロックなど) に関連するいわゆるクラスキーを「アンロック」するために使用できます。

iOS ファイルシステムに格納されているすべてのファイルはファイルメタデータに含まれている独自の個別ファイルごとの鍵で暗号化されています。メタデータはファイルシステムキーで暗号化され、クラスキーのひとつでラップされます。クラスキーはファイルを作成する際にアプリにより選択された保護クラスに依存します。

<img src="Images/Chapters/0x06d/key_hierarchy_apple.jpg" width="500px"/>
*iOS Data Protection 鍵階層 <sup>[3]</sup>*

ファイルには4つの保護クラスのいずれかを割り当てることができます。

- 完全保護 (NSFileProtectionComplete): このクラスキーはユーザーパスコードとデバイス UID から導出される鍵で保護されます。デバイスがロックされた直後にメモリから消去され、ユーザーがデバイスをアンロックするまでデータにアクセスできなくなります。

- オープンするまで保護 (NSFileProtectionCompleteUnlessOpen): 完全保護と同様の動作をしますが、アンロック状態でファイルを開くと、ユーザーがデバイスをロックしてもアプリはファイルにアクセスできます。これは非対称楕円曲線暗号を使用して実装されています <sup>[3]</sip> 。

- 最初のユーザー認証まで保護 (NSFileProtectionCompleteUntilFirstUserAuthentication): このファイルはユーザーが起動後初めてデバイスをアンロックした瞬間からアクセスできます。後でユーザーがデバイスをロックした場合でもアクセスできます。

- 保護なし (NSFileProtectionNone): このクラスキーは UID でのみ保護され、Effaceable Storage に保存されます。この保護クラスは迅速なリモートワイプを可能にするために存在します。クラスキーが即座に削除されるとデータはアクセス不可になります。

<code>NSFileProtectionNone</code> を除くすべてのクラスキーはデバイスの UID とユーザーのパスコードから導出された鍵で暗号化されています。その結果、復号化はデバイス自体でのみ発生し、正しいパスコードを入力する必要があります。

iOS 7 以降、デフォルトデータ保護クラスは「最初のユーザー認証まで保護」となっています。

##### キーチェーン

iOS キーチェーンは暗号鍵やセッショントークンなどの短く機密性の高いデータを安全に保管するために使用されます。キーチェーン API を介してのみアクセスできる SQLite データベースとして実装されています。キーチェーンデータベースはデバイスキーとユーザー PIN やパスワード (ユーザーによって設定されている場合) を使用して暗号化されています。

デフォルトでは、各アプリは自分で作成したキーチェーンにのみアクセスできます。但し、「アクセスグループ」機能を使用して同じ開発者が署名したアプリ間でアクセスを共有することはできます。キーチェーンへのアクセスは <code>securityd</code> デーモンにより管理され、アプリの <code>Keychain-access-groups</code>, <code>application-identifier</code>, <code>application-group</code> エンタイトルメントに基づいてアクセスを許可します。

キーチェーン API は自己説明的な名称の以下の主要な操作で構成されています。

- SecItemAdd
- SecItemUpdate
- SecItemCopyMatching
- SecItemDelete

キーチェーンデータはファイルの暗号化に使用されるものと同様のクラス構造を使用して保護されています。キーチェーンに追加されたアイテムはバイナリ plist としてエンコードされ、アイテムごとに 128 ビットの AES 鍵を使用して暗号化されます。より大きなサイズのデータはキーチェーンに直接保存されることはないことに注意します。それは Data Protection API の対象となります。データ保護は <code>kSecAttrAccessible</code> 属性を設定した <code>SecItemAdd</code> や <code>SecItemUpdate</code> コールで有効になります。以下の設定を利用できます。

- kSecAttrAccessibleAfterFirstUnlock: キーチェーンアイテムのデータは再起動後デバイスがユーザーにより一度アンロックされるまでアクセスできません。
- kSecAttrAccessibleAlways: キーチェーンアイテムのデータはデバイスがロックされているかどうかにかかわらず常にアクセスできます。
- kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: キーチェーンのデータはデバイスがアンロックされている場合のみアクセスできます。デバイスにパスコードが設定されている場合のみ使用できます。データは iCloud や iTunes のバックアップには含まれません。
- kSecAttrAccessibleAlwaysThisDeviceOnly: キーチェーンアイテムのデータはデバイスがロックされているかどうかにかかわらず常にアクセスできます。データは iCloud や iTunes のバックアップには含まれません。
- kSecAttrAccessibleWhenUnlocked: キーチェーンアイテムのデータはユーザーによりデバイスがアンロックされている間のみアクセスできます。
- kSecAttrAccessibleWhenUnlockedThisDeviceOnly: キーチェーンアイテムのデータはユーザーによりデバイスがアンロックされている間のみアクセスできます。データは iCloud や iTunes のバックアップには含まれません。

#### 静的解析

iOS アプリのソースコードにアクセスできる時には、アプリ全体を通して保存および処理される機密データを見つけます。これには一般的なパスワード、秘密鍵、個人識別情報 (PII) が含まれますが、業界の規制、法律、社内ポリシーを通じて機密と判断されるその他のデータも含まれます。下記のローカルストレージ API を使用して、このデータが保存されるインスタンスを探します。機密データが適切な保護なしで格納されていないことを確認します。例えば、認証トークンを追加の暗号化なしで NSUserDefaults に保存してはいけません。いずれの場合でも、秘密鍵がセキュアな設定 (理想的には、<code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code>) を使用するキーチェーンに格納されるように暗号化を実装する必要があります。

iOS アプリで安全でないデータストレージのインスタンスを探す際には、データを格納する以下のような手段を考慮すべきです。

##### CoreData/SQLite データベース

* `Core Data` <sup>[10]</sup>: アプリケーションのオブジェクトのモデルレイヤーを管理するために使用するフレームワークです。オブジェクトライフサイクルおよびオブジェクトグラフ管理(persistenceを含む)に関連する一般的なタスクに一般化および自動化されたソリューションを提供します。Core Data はより低いレベルの sqlite データベースで動作します。

* `sqlite3`: `libsqlite3.dylib` ライブラリをアプリケーションに追加する必要があります。このライブラリは SQLite コマンドに API を提供する C++ ラッパーです。

##### NSUserDefaults

`NSUserDefaults` <sup>[11]</sup> クラスは default システムと対話するためのプログラム的なインタフェースを提供します。default システムではアプリケーションはユーザーの好みに合わせて動作をカスタマイズできます。NSUserDefaults によって保存されたデータはアプリケーションバンドルから閲覧できます。また plist ファイルにデータを保存しますが、データ量が少なくて済みます。

##### ファイルシステム

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

重要なファイルシステムの場所は以下の通りです。

* AppName.app
  * アプリのバンドル、アプリとそのすべてのリソースが含まれています
  * ユーザーには見えますが、ユーザーはこのディレクトリに書き込むことができません
  * このディレクトリの内容はバックアップされません
* Documents/
  * このディレクトリを使用して、ユーザーが作成したコンテンツを格納します
  * ユーザーに見えており、ユーザーはこのディレクトリに書き込むことができます
  * このディレクトリの内容はバックアップされます
  * アプリは `NSURLIsExcludedFromBackupKey` を設定することによりパスを無効にできます
* Library/
  * これはユーザーデータファイルではないファイルのための最上位ディレクトリです
  * iOS アプリは一般的に `Application Support` と `Caches` サブディレクトリを使用しますが、カスタムサブディレクトリを作成することもできます
* Library/Caches/
  * 半永続的なキャッシュファイル
  * ユーザーには見えず、ユーザーはこのディレクトリに書き込むこともできません
  * このディレクトリの内容はバックアップされません
  * OS はアプリが実行されていないときに自動的にファイルを削除することがあります (ストレージ容量が不足しているなど)
* Library/Application Support/
  * アプリを実行するために必要な永続的なファイル
  * ユーザーには見えず、ユーザーはこのディレクトリに書き込むこともできません
  * このディレクトリの内容はバックアップされます
  * アプリは `NSURLIsExcludedFromBackupKey` を設定することによりパスを無効にできます
* tmp/ 
  * このディレクトリを使用して、アプリの実行中に維持する必要のない一時ファイルを書き込みます
  * 非永続的なキャッシュファイル
  * ユーザーにいは見えません
  * このディレクトリの内容はバックアップされません
  * OS はアプリが実行されていないときに自動的にファイルを削除することがあります (ストレージ容量が不足しているなど)

より詳細な解析には、IntroSpy などの API 監視ツールを使用してアプリを計装します。

動的解析の中で必要な場合には、「セキュリティテスト入門 (iOS)」の章で説明しているように keychain dumper <sup>[9]</sup> を使用してキーチェーンの内容をダンプできます。キーチェーンファイルは以下の場所にあります。

```
/private/var/Keychains/keychain-2.db
```

#### 改善方法

機密データを格納するにはハードウェア支援のストレージメカニズムを使用する必要があります。機密データを格納するために許可される選択肢は以下の通りです。

- `kSecAttrAccessibleWhenUnlocked` 属性でキーチェーンにデータを格納する。
- 格納する前に標準の暗号 API を使用してデータを暗号化し、キーチェーンに暗号鍵を格納する。
- `NSFileProtectionComplete` 属性でファイルを作成する。

以下の例は `createFileAtPath` メソッドを使用して安全に暗号化されたファイルを作成する方法を示しています。

```objective-c
[[NSFileManager defaultManager] createFileAtPath:[self filePath]
  contents:[@"secret text" dataUsingEncoding:NSUTF8StringEncoding]
  attributes:[NSDictionary dictionaryWithObject:NSFileProtectionComplete
  forKey:NSFileProtectionKey]];
```

キーチェーンを使用してデータを保存、更新、削除する一般的な例は公式の Apple ドキュメント <sup>[12]</sup> にあります。

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
[9] Keychain Dumper - https://github.com/ptoomey3/Keychain-Dumper/
[10] Core Data iOS - https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/CoreData/nsfetchedresultscontroller.html#//apple_ref/doc/uid/TP40001075-CH8-SW1
[11] NSUserDefaults - https://developer.apple.com/documentation/foundation/nsuserdefaults
[12] GenericKeyChain - https://developer.apple.com/library/content/samplecode/GenericKeychain/Introduction/Intro.html#//apple_ref/doc/uid/DTS40007797-Intro-DontLinkElementID_2


### 機密データに関するテスト(ログ)

#### 概要

モバイルデバイス上にログファイルを作成する理由は正当な理由はたくさんあります。例えば、クラッシュやエラーを追跡するため、オフラインであるときローカルに格納し、再びオンラインになってアプリケーション開発者/企業に送信します。使用統計情報にも使用されます。但し、クレジットカード番号やセッション ID などの機密データを記録すると攻撃者や悪意のあるアプリケーションにデータが公開される可能性があります。
ログファイルはさまざまな方法で作成されます。以下のリストは iOS で利用できるメカニズムを示しています。

* NSLog メソッド
* printf系の関数
* NSAssert系の関数
* マクロ

#### 静的解析

以下のキーワードを使用して定義済みやカスタムのロギングステートメントの使用についてアプリソースコードを確認します。
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
* V2.2: "機密データがアプリケーションログに書き込まれていない。"

##### CWE
* CWE-117: Improper Output Neutralization for Logs
* CWE-532: Information Exposure Through Log Files
* CWE-534: Information Exposure Through Debug Log Files

##### ツール
* Xcode


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

外部サービスに対するすべてのリクエストに対して、機密情報が埋め込まれていないか解析する必要があります。傍受プロキシを使用することで、アプリからサードパーティのエンドポイントまでのトラフィックを調べることができます。アプリを使用するときには、主要機能がホストされているサーバーに直接接続されていないすべてのリクエストに対して、機密データがサードパーティへ送信されていないかチェックする必要があります。例えば、これにはトラッカーや広告サービスの PII (個人識別情報) があります。

#### 改善方法

サードパーティサービスに送信されるすべてのデータは匿名化される必要があります。そのため、サードパーティがユーザーアカウントを識別できる PII データはありません。また、ユーザーアカウントやセッションにマップできるアプリケーション内の ID などの他のすべてのデータもサードパーティに送信してはいけません。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
* V2.3: "機密データはアーキテクチャに必要な部分でない限りサードパーティと共有されていない。"

##### CWE
* CWE-359 "Exposure of Private Information ('Privacy Violation')": [Link to CWE issue]

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

  ```#ObjC
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
  ```

* Xcode の `Interface Builder` で xib と storyboard ファイルを開き、適切なオブジェクトの `Attributes Inspector` の `Secure Text Entry` と `Correction` の状態を確認します。

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

```#ObjC
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

プロセス間通信 (IPC) はプロセスが相互にメッセージやデータを送信できるようにする方法です <sup>[1]</sup> 。二つのプロセスが相互に通信する必要がある場合に、iOS 上で IPC を実装するさまざまな方法が利用できます。

* **XPC サービス** <sup>[3]</sup>: XPC は基本的なプロセス間通信を提供し、`launchd` により管理される、構造化された非同期プロセス間通信ライブラリです。これは可能な限り制限された環境で実行されます。最小限のファイルシステムアクセス、ネットワークアクセス、ルート権限昇格なしでサンドボックス化されています。XPC サービスには、二つの異なる API があります。
  * NSXPCConnection API
  * XPC Services API
* **Mach ポート**<sup>[5]</sup>: すべての IPC 通信は Mach Kernel API に依存しています。Mach ポートは (同じデバイス上の) ローカル通信のみ許可します。それらはネイティブに実装することも、Core Foundation (CFMachPort) や Foundation (NSMachPort) ラッパーを使用することも可能です。
* **NSFileCoordinator**: NSFileCoordinator クラスはさまざまなプロセスに対してローカルファイルシステム上でアクセス可能なファイルを介して、アプリ間のデータを管理及び交換するために使用できます。


#### 静的解析

以下のセクションでは、iOS のソースコード内の IPC 実装を識別するために探す必要があるさまざまなキーワードをまとめています。

##### XPC サービス

NSXPCConnection API を実装する際には、いくつかのクラスを使用できます。

* NSXPCConnection
* NSXPCInterface
* NSXPCListener
* NSXPCListenerEndpoint

接続にはいくつかのセキュリティ属性を設定して検証する必要があります <sup>[7]</sup> 。

C ベースの XPC Services API では、Xcode プロジェクトで以下の二つのファイルの可用性をチェックする必要があります。

* xpc.h <sup>[4]</sup>
* connection.h

##### Mach ポート

低レベルの実装で探すキーワードです。
* mach_port_t
* mach_msg_*

高レベルの実装 (Core Foundation や Foundation ラッパー) で探すキーワードです。
* CFMachPort
* CFMessagePort
* NSMachPort
* NSMessagePort


##### NSFileCoordinator

検索キーワードです。
* NSFileCoordinator

#### 動的解析

IPC メカニズムは iOS ソースコードの静的解析を介して検証する必要があります。現時点で IPC の使用状況を検証するために iOS 上で利用可能なツールはありません。


#### 改善方法

XPC サービスは iOS 上で IPC を実装する際に最もセキュアで柔軟な方法であり、優先的に使用すべきです。

NSFileCoordinator <sup>[6]</sup> メソッドは同期的に実行されるため、コードは完了するまでブロックされます。これは非同期ブロックコールバックを待つ必要がないため便利です。しかし、現在のスレッドをブロックすることも意味します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.6: "機密データがIPCメカニズムを介して公開されていない。"

##### CWE
- CWE-634 - Weaknesses that Affect System Processes

#### その他
[1] iPhoneDevWiki IPC - http://iphonedevwiki.net/index.php/IPC
[2] Inter-Process Communication - http://nshipster.com/inter-process-communication/
[3] XPC Services - https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html
[4] xpc.h - https://developer.apple.com/documentation/xpc/xpc_services_xpc.h
[5] NSMachPort - https://developer.apple.com/documentation/foundation/nsmachport
[6] NSFileCoordinator - http://www.atomicbird.com/blog/sharing-with-app-extensions
[7] Security Attributes of NSXPCConnection -  https://www.objc.io/issues/14-mac/xpc/#security-attributes-of-the-connection


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

他の最新のモバイルオペレーティングシステムと同様に、iOS はデバイス上のデータのコピーを作成する自動バックアップ機能を提供します。iOS では、バックアップは iTunes を介して行うか、iCloud バックアップ機能を使用してクラウドを介して行います。いずれの場合でも、バックアップはデバイス上のほぼすべてのデータを含みますが、Apple Pay 情報や TouchID 設定などの一部の非常に機密性の高いものは除きます。

iOS はインストールされたアプリとそのデータをバックアップするので、アプリに格納される機密性のあるユーザーデータが意図せずバックアップを介して漏洩するかどうかが明らかに懸念されます。この質問の答えは「はい」ですが、アプリがそもそも機密データをセキュアではなく格納している場合に限ります。

##### キーチェーンはどのようにバックアップされているか

ユーザーが自分の iPhone をバックアップすると、キーチェーンデータもバックアップされますが、キーチェーン内の秘密は暗号化されたままです。キーチェーンデータを復号化するために必要なクラスキーはバックアップには含まれません。キーチェーンデータを復元するには、バックアップはデバイスに復元する必要があり、そのデバイスは同じパスコードでアンロックする必要があります。

<code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> 属性がセットされたキーチェーンアイテムは、バックアップが同じデバイスに復元される場合にのみ復号化できます。バックアップからこのキーチェーンデータを抽出しようとする悪意のあるユーザーは、元のデバイス内の暗号ハードウェアにアクセスすることなくそれを復号化することはできません。

注意点：この章の前半で推奨されるように機密データが処理される (キーチェーンに格納される、もしくはキーチェーン内にロックされた鍵で暗号化されている) 限り、バックアップは問題ではありません。

#### 静的解析

<code>NSURLIsExcludedFromBackupKey</code> <sup>[1]</sup> や <code>CFURLIsExcludedFromBackupKey</code> <sup>[2]</sup> ファイルシステムプロパティを使用してバックアップからファイルやディレクトリを除外できます。多数のファイルを除外する必要があるアプリでは、独自のサブディレクトリを作成し、そのディレクトリを除外としてマークすることでファイルを除外できます。アプリはシステム定義のディレクトリを除外するのではなく、独自の除外ディレクトリを作成すべきです。

これらの API はそれぞれ、拡張属性を直接設定する古く非推奨の方式よりも優先されます。iOS 5.1 および以降で動作するすべてのアプリはこれらの API を使用してバックアップからデータを除外すべきです。

以下は iOS 5.1 および以降でファイルをバックアップから除外するサンプルコートです (Objective-C) <sup>[3]</sup> 。

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

以下は iOS 5.1 および以降でファイルをバックアップから除外するサンプルコートです (Swift) <sup>[3]</sup> 。

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

アプリが iOS 5.0.1 をサポートする必要がある場合は、以下のメソッドを使用して "do not back up" 拡張属性を設定できます。バックアップすべきではないファイルやフォルダを作成するときには、データをファイルに書き込んでからファイルに URL を渡して、以下のメソッドをコールします <sup>[3]</sup> 。

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


#### 静的解析

使用されているかどうか iOS モバイルアプリケーションのソースコードをレビューします。
#### 動的解析

アプリデータがバックアップされた後、バックアップファイルやフォルダのデータ内容をレビューします。具体的には、以下のディレクトリをレビューして機密データが含まれているかどうかを確認すべきです。

* Documents/
* Library/Caches/
* Library/Application Support/
* tmp/

前述の各ディレクトリの目的やそれらに格納される情報の種類についての詳細は、このセクションの概要を参照します。

#### 改善方法

特定のモバイルアプリケーションがインストールされているデバイスの iTunes バックアップを実行する際、バックアップにはすべてのサブディレクトリ (`Library/Caches/` サブディレクトリを除く) とデバイスのファイルシステム上のそのアプリのプライベートディレクトリに含まれるファイルが含まれます <sup>[4]</sup> 。

そのため、アプリのプライベートディレクトリやサブディレクトリ内の任意のファイルやフォルダ内に平文で機密データを格納することは避けます。

`Documents/` および `Library/Application Support/` 内のすべてのファイルはデフォルトで常にバックアップされていますが、`NSURLIsExcludedFromBackupKey` キーを使用して `[NSURL setResourceValue:forKey:error:]` をコールすることでバックアップからファイルを除外することができます <sup>[5]</sup> 。

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
