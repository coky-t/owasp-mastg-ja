## データストレージのテスト

すべてのテストケースについてアプリのコンテキストでどのような機密情報があるかを知る必要があります。詳細については「データの分類」をご覧ください。

### ローカルデータストレージのテスト

#### 概要

多くのモバイルアプリケーションではデータを格納することが不可欠です。例えば、ユーザー設定やユーザーが入力したデータを追跡してローカルやオフラインで格納する必要があります。データはさまざまなオペレーティングシステムでさまざまな方法でモバイルアプリケーションにより永続的に格納されます。以下は iOS プラットフォームで使用できるメカニズムを示しています。通常、機密データを格納することは考慮されません。

* CoreData/SQLite データベース
* NSUserDefaults
* プロパティリスト (Plist) ファイル
* プレーンファイル

#### 静的解析

理想的には機密情報はデバイスに格納すべきではありません。機密情報をデバイス自体に格納する必要がある場合、キーチェーンなどを使用して iOS デバイスのデバイスを保護するために利用できる関数/API呼び出しがあります。

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


#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.5: "機密データを含む可能性があるテキストフィールドでは、クリップボードが無効化されている。"

##### CWE
- CWE

#### Info
[1] Disable clipboard on iOS - http://stackoverflow.com/questions/1426731/how-disable-copy-cut-select-select-all-in-uitextview



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

-- TODO [Add content on overview of "Testing for Sensitive Data in Backups"] --

#### 静的解析

-- TODO [Add content on white-box testing of "Testing for Sensitive Data in Backups"] --

#### 動的解析

-- TODO [Add content on black-box testing of "Testing for Sensitive Data in Backups"] --

#### 改善方法

-- TODO [Add content on remediation of "Testing for Sensitive Data in Backups"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.8: "機密データがモバイルオペレーティングシステムにより生成されるバックアップに含まれていない。"

##### CWE
- CWE

#### Info
-- TODO [Add references for "Testing for Sensitive Data in Backups"] --



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
