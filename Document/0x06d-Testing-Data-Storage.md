## データストレージのテスト

### ローカルデータストレージのテスト -- TODO [Merge with OWASP-DATAST-001-2] --

#### 概要

-- TODO [Create content for "Testing Local Data Storage" on iOS] --

#### ブラックボックステスト

資格情報や鍵などの機密情報が安全でない状態で格納されていて iOS のネイティブ関数を利用していないかどうかを特定する方法はアプリのデータディレクトリを解析することです。アプリは特定の機能がユーザーによってトリガーされたときにのみシステム資格情報を格納する可能性があるため、データを解析する前に可能な限り多くのアプリ機能を実行することが重要です。一般的なキーワードとアプリ固有のデータに基づいて、データダンプに対して静的解析を実行します。アプリケーションが iOS デバイスのローカルにデータを格納する方法を特定します。アプリケーションがデータをローカルに格納するための選択肢には以下の可能性があります。

* CoreData/SQLite データベース
* NSUserDefaults
* プロパティリスト (Plist) ファイル
* プレーンファイル

手順 :

1. 潜在的な機密データを格納する機能をトリガーします。
2. iOS デバイスに接続して次のディレクトリを参照します(これは iOS バージョン 8.0 以降に適用されます)。 `/var/mobile/Containers/Data/Application/$APP_ID/`
3. 格納されたデータに次のような grep コマンドを実行します。 `grep -irn "USERID"`
4. 機密データがプレーンテキストに格納されている場合、このテストは失敗となります。

また、デバッグなどの手動による動的解析を利用して、特定のシステム資格情報がデバイス上でどのように格納および処理されるかを検証することもできます。このアプローチは時間がかかり手動で実行される可能性が高いため、特定のユースケースでのみ実行します。

#### ホワイトボックステスト

ソースコードを調べる際には、iOS によって提供されるネイティブ機能が識別された機密情報に適用されているかどうかを分析する必要があります。理想的には機密情報は一切デバイスに格納してはいけません。機密情報をデバイス自体に格納する必要がある場合には、キーチェーンなどを使用して iOS デバイス上のデータを保護するための関数/APIコールが利用できます。

#### 改善方法

機密情報(資格情報、鍵、PIIなど)がデバイス上でローカルに必要な場合、車輪を再発明したりデバイス上で暗号化せずに残す代わりに、iOS によって安全にデータを格納するために使用すべきいくつかのベストプラクティスが提供されています。

以下は証明書や鍵や機密情報の安全な保管に一般的に使用されるベストプラクティスのリストです。
* 証明書や鍵などの少量の機密データについては [Keychain Services](https://developer.apple.com/reference/security/1658642-keychain_services?language=objc) を使用して、デバイス上のローカルに安全に保管します。キーチェーンデータはファイルデータ保護で使用されるものと同様のクラス構造を使用して保護されています。これらのクラスはファイルデータ保護クラスと同等の振る舞いをしますが、別のキーを使用する異なる名前のAPIの一部です。デフォルトのビヘイビアは `kSecAttrAccessibleWhenUnlocked` です。詳細は使用可能なモード [Keychain Item Accessibility](https://developer.apple.com/reference/security/1658642-keychain_services/1663541-keychain_item_accessibility_cons) を参照ください。
* ローカルファイルを暗号化または復号化するために独自実装した暗号化機能は避けるべきです。
* OMTG-DATAST-001-2 の章で示すように資格情報や鍵などの機密情報に対する安全でないストレージ機能を避けます。


#### 参考情報

* [Keychain Services Programming Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/iPhoneTasks/iPhoneTasks.html)
* [IOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)

### 機密データ漏洩に関するテスト(ローカルストレージ)

#### 概要

多くのモバイルアプリケーションではデータを格納することが不可欠です。例えば、ユーザー設定やユーザーが入力したデータを追跡してローカルやオフラインで格納する必要があります。データはさまざまなオペレーティングシステムでさまざまな方法でモバイルアプリケーションにより永続的に格納されます。以下は iOS プラットフォームで使用できるそれらのメカニズムを示しています。

* CoreData/SQLite データベース
* NSUserDefaults
* プロパティリスト (Plist) ファイル
* プレーンファイル


#### ブラックボックステスト

意図したとおりにアプリをインストールし使用します。アプリは特定の機能がユーザーによってトリガーされたときにのみシステム資格情報を格納する可能性があるため、データを解析する前に可能な限り多くのアプリ機能を実行することが重要です。その後、以下の項目を確認します。

-- TODO [Further develop section on black-box testing of "Testing for Sensitive Data Disclosure in Local Storage"] --


#### ホワイトボックステスト

##### CoreData/SQLite データベース

- `Core Data` はアプリケーションのモデルレイヤーオブジェクトを管理するために使用するフレームワークです。オブジェクトライフサイクルおよびオブジェクトグラフ管理(persistenceを含む)に関連する一般的なタスクに一般化および自動化されたソリューションを提供します。Core Data はより低いレベルの sqlite データベースで動作します。

- `sqlite3`: フレームワークセクションの‘libsqlite3.dylib’ライブラリはアプリケーションに追加する必要があります。SQLite コマンドに API を提供する C++ ラッパーです。


##### NSUserDefaults

`NSUserDefaults` クラスは defaults システムと対話するためのプログラム的なインタフェースを提供します。defaults システムではアプリケーションはユーザーの好みに合わせて動作をカスタマイズできます。NSUserDefaults によって保存されたデータはアプリケーションバンドルから閲覧できます。また plist ファイルにデータを保存しますが、データ量が少なくて済みます。

##### プレーンファイル / Plist ファイル

* `NSData`: NSData は静的データオブジェクトを作成し、NSMutableData は動的データオブジェクトを作成します。NSData と NSMutableData は通常データストレージとして使用されますが、データオブジェクトに含まれるデータをアプリケーション間でコピーや移動ができる、分散オブジェクトアプリケーションでも役に立ちます。
  * NSData オブジェクトの書き込むために使用されるメソッドのオプション: `NSDataWritingWithoutOverwriting, NSDataWritingFileProtectionNone, NSDataWritingFileProtectionComplete, NSDataWritingFileProtectionCompleteUnlessOpen, NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication`
  * NSData クラスの一部としてデータを格納する: `writeToFile`
* ファイルパスを管理する:  `NSSearchPathForDirectoriesInDomains, NSTemporaryDirectory`
* `NSFileManager` オブジェクトはファイルシステムの内容を調べて変更することができます。`createFileAtPath` でファイルを作成して書き込みます。

#### 改善方法

-- TODO [Add content on remediation on "Testing for Sensitive Data Disclosure in Local Storage"]

#### 参考情報

* [File System Basics](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html)
* [Foundation Functions](https://developer.apple.com/reference/foundation/1613024-foundation_functions)
* [NSFileManager](https://developer.apple.com/reference/foundation/nsfilemanager)
* [NSUserDefaults](https://developer.apple.com/reference/foundation/userdefaults)

### 機密データに関するテスト(ログ)

#### 概要

モバイルデバイス上にログファイルを作成する理由は正当な理由はたくさんあります。例えば、クラッシュやエラーを追跡するため、オフラインであるときローカルに格納し、再びオンラインになってアプリケーション開発者/企業に送信します。使用統計情報にも使用されます。但し、クレジットカード番号やセッション ID などの機密データを記録すると攻撃者や悪意のあるアプリケーションにデータが公開される可能性があります。
ログファイルはさまざまなオペレーティングシステムでさまざまな方法で作成されます。以下のリストは iOS で利用できるメカニズムを示しています。

* NSLog メソッド
* printf系の関数
* NSAssert系の関数
* マクロ

機密情報の分類は業種、国、法律、規制によって異なります。したがって適用される法律や規制を知っておく必要があり、実際にアプリのコンテキスト内でどのような機密情報があるかを認識する必要があります。

#### ブラックボックステスト

ユーザーが機密情報を入力するための入力フィールドがある iOS アプリケーションのページに進みます。ログファイル内の機密データをチェックするには以下の2つの方法があります。

* iOS デバイスに接続して以下のコマンドを実行します。
```
tail -f /var/log/syslog
```

* iOS デバイスを USB 経由で接続して Xcode を起動します。Windows > Devices に移動し、デバイスとそれぞれのアプリケーションを選択します。

入力フィールドのプロンプトを完了した後、上記のコマンドの出力に機密データが表示されている場合、このテストは失敗となります。


#### ホワイトボックステスト

以下のキーワードを使用して定義済み/カスタムのロギングステートメントの使用についてソースコードを確認します。
* 定義済みおよびビルトイン関数の場合：
  * NSLog
  * NSAssert
  * NSCAssert
  * fprintf
* カスタム関数の場合：
  * Logging
  * Logfile


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

-- TODO [Add references for section "Testing for Sensitive Data in Logs"] --

### 機密データがサードパーティに送信されているかのテスト

#### 概要

-- TODO [Add content to overview of "Testing Whether Sensitive Data Is Sent to Third Parties" ] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing of "Testing Whether Sensitive Data Is Sent to Third Parties"] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing of "Testing Whether Sensitive Data Is Sent to Third Parties"] --

#### 改善方法

-- TODO [Add content on remediation of "Testing Whether Sensitive Data Is Sent to Third Parties"] --

#### 参考情報

-- TODO [Add references for "Testing Whether Sensitive Data Is Sent to Third Parties"] --

### 機密データに関するテスト(キーボードキャッシュ)

#### 概要

キーボード入力を簡素化するため、オートコレクト、予測入力、スペルチェックなどを提供します。キーボード入力のほとんどはデフォルトで /private/var/mobile/Library/Keyboard/dynamic-text.dat にキャッシュされます。

この動作は、UITextField, UITextView, UISearchBar で採用されている UITextInputTraits プロトコルによって実現されます。キーボードキャッシュは以下のプロパティの影響を受けます。

* `var autocorrectionType: UITextAutocorrectionType` はタイピング中にオートコレクトが有効か無効かを決定します。オートコレクトを有効にすると、テキストオブジェクトは未知語を追跡してより適切な置換候補をユーザーに提案します。ユーザーが明示的にアクションをオーバーライドしない限り、自動的に入力したテキストを置換します。このプロパティのデフォルト値は `UIText​Autocorrection​Type​Default` です。ほとんどの入力メソッドはオートコレクトが有効になります。
* `var secureTextEntry: BOOL` はテキストコピーやテキストキャッシュを無効にするべきかどうかを識別し、UITextField の場合は入力されるテキストを隠します。このプロパティはデフォルトで `NO` に設定されています。

#### ブラックボックステスト

1. iOS デバイスのキーボードキャッシュをリセットします。設定 > 一般 > リセット > キーボードの変換学習をリセット

2. アプリケーションの機能を使用していきます。ユーザーが機密データを入力できる機能を特定します。

3. 以下のディレクトリにあるキーボードキャッシュファイル dynamic-text.dat をダンプします(8.0 未満の iOS では異なる場合があります)。
/private/var/mobile/Library/Keyboard/

4. ユーザー名、パスワード、電子メールアドレス、クレジットカード番号などの機密データを探します。機密データがキーボードキャッシュファイルから取得できる場合、このテストは失敗となります。

#### ホワイトボックステスト

キーボードキャッシュを無効にする実装があるかどうかは開発者に直接確認します。

* 提供されたソースコードを検索して、以下と同様の実装を探します。

  ```
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
  ```
* Interface Builder で xib と storyboard ふぁいるを開き、適切なオブジェクトの Attributes Inspector の Secure Text Entry and Correction の状態を確認します。

#### 改善方法

アプリケーションはテキストフィールドに入力された機密情報を含むデータをキャッシュしないことを保証する必要があります。これは目的の UITextFields, UITextViews, UISearchBars で `textObject.autocorrectionType = UITextAutocorrectionTypeNo` ディレクティブを使用して、プログラムで機能を無効にすることで実現できます。PIN やパスワードなどのマスクする必要のあるデータについては、`textObject.secureTextEntry` に `YES` を設定します。

```#ObjC
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

#### 参考情報

* [UIText​Input​Traits protocol](https://developer.apple.com/reference/uikit/uitextinputtraits)


### 機密データに関するテスト(クリップボード)

#### 概要

-- TODO [Add content on overview of "Testing for Sensitive Data in the Clipboard"] --

#### ブラックボックステスト

ユーザーにユーザー名、パスワード、クレジットカード番号などの機密情報を指示する入力フィールドがあるアプリケーションのビューに進みます。

何かしらの値を入力して入力フィールドをダブルタップします。

「選択」「全選択」「ペースト」オプションが表示されている場合、「選択」または「全選択」オプションをタップすると、「カット」「コピー」「ペースト」が使えます。

ペーストにより値を取得することができるため、機密入力フィールドでは「カット」および「コピー」オプションは無効にする必要があります。

機密入力フィールドで内容を「カット」または「コピー」することができる場合、このテストは失敗となります。

#### ホワイトボックステスト

提供されたソースコードを検索して、`UITextField` のサブクラス実装を探します。

```
@interface name_of_sub_class : UITextField
action == @select(cut:)
action == @select(copy:)
```

#### 改善方法

以下の改善方法が考えられます。

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

http://stackoverflow.com/questions/1426731/how-disable-copy-cut-select-select-all-in-uitextview

#### 参考情報

-- TODO [Add references for "Testing for Sensitive Data in the Clipboard"] --

### 機密データがIPCメカニズムを介して漏洩しているかのテスト

#### 概要

-- TODO [Add content on overview of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing of "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 改善方法

-- TODO [Add remediation on "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

#### 参考情報

-- TODO [Add references for "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"] --

### ユーザーインタフェースを介しての機密データ漏洩に関するテスト

##### 概要

-- TODO [Add content on overview for "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 改善方法

-- TODO [Add remediation of "Testing for Sensitive Data Disclosure Through the User Interface"] --

#### 参考情報

-- TODO [Add references for "Testing for Sensitive Data Disclosure Through the User Interface"] --

### 機密データに関するテスト(バックアップ)

#### 概要

-- TODO [Add content on overview of "Testing for Sensitive Data in Backups"] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing of "Testing for Sensitive Data in Backups"] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing of "Testing for Sensitive Data in Backups"] --

#### 改善方法

-- TODO [Add content on remediation of "Testing for Sensitive Data in Backups"] --

#### 参考情報

-- TODO [Add references for "Testing for Sensitive Data in Backups"] --

### 自動生成されるスクリーンショットの機密情報に関するテスト

#### 概要

製造業者はアプリケーションへの出入りの際に美的で魅力的な効果をデバイスユーザーに提供したいため、アプリケーションがバックグラウンドになるとスクリーンショットを保存するというコンセプトが導入されました。この機能は機密情報を含むスクリーンショット(電子メールや企業文書のスクリーンショットなど)がローカルストレージに書き込まれるため、アプリケーションにセキュリティリスクを引き起こす可能性があります。脱獄されたデバイス上の不正なアプリケーションやデバイスを盗む何者かによって取得される可能性があります。

#### ブラックボックステスト

アプリケーション上でユーザー名、電子メールアドレス、アカウント詳細などの機密情報を表示するページに進みます。iOS デバイスのホームボタンを押して、アプリケーションをバックグラウンドにします。iOS デバイスに接続して以下のディレクトリに進みます(8.0 未満の iOS では異なる場合があります)。

`/var/mobile/Containers/Data/Application/$APP_ID/Library/Caches/Snapshots/`

アプリケーションがスクリーンショットとして機密情報ページをキャッシュしている場合、このテストは失敗となります。

アプリケーションがバックグラウンドに入るたびにキャッシュされるデフォルトのスクリーンショットを持つことを強く推奨します。

#### ホワイトボックステスト

ソースコードを解析する中で、機密データが含まれるフィールドや画面を探します。アプリケーションがバックグラウンドされる前に画面をサニタイズするかどうかを特定します。

#### 改善方法

デフォルトのスクリーンショットを設定する改善方法が考えられます。

```ObjC
@property (UIImageView *)backgroundImage;
 
- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    [self.window addSubview:myBanner];
}
```
これによりアプリケーションがバックグラウンドされるときはいつでもバックグラウンドイメージに "overlayImage.png" が設定されます。"overlayImage.png" は常に現在の view を上書きするため、機密データの漏洩を防ぎます。

#### 参考情報

-- TODO [Add references for "Testing For Sensitive Information in Auto-Generated Screenshots" ] --

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

##### OWASP Mobile Top 10

* M1 - Improper Platform Usage

##### CWE

- CWE: -- TODO [Add link to CWE issue] --


### ユーザー通知コントロールの検証

#### 概要

ユーザーに通知することはモバイルアプリの使用における重要な要素です。多くのセキュリティコントロールがすでに導入されていたとしても、ユーザーによって迂回や誤用される可能性があります。

以下のリストは最初にアプリを開いて使用する際の仮想的な警告またはアドバイスを示しています。
* アプリは初回起動後にローカルおよびリモートに格納されているデータのリストを表示します。情報が広い範囲におよぶ可能性があるため、外部リソースへリンクすることも可能です。
* アプリ内で新規ユーザーアカウントを作成する場合、提供されたパスワードがセキュアでありベストプラクティスパスワードポリシーに当てはまるかどうかをユーザーに表示します。
* ユーザーがルート化デバイスにアプリをインストールする場合、危険であり、OS レベルのセキュリティコントロールを無効にし、マルウェアに感染されやすくなるという警告を表示します。詳細は OMTG-DATAST-011 も参照ください。
* ユーザーが古いバージョンの Android にアプリをインストールする場合、警告を表示します。詳細は OMTG-DATAST-010 も参照ください。

-- TODO [What else can be a warning on Android?] --

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

##### OWASP Mobile Top 10

* M1 - Improper Platform Usage

##### CWE
- CWE: -- TODO [Add link to CWE issue for "Verifying User Education Controls"] --
