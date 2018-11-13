## iOS のプラットフォーム API

### アプリパーミッションのテスト

#### 概要
iOS はすべてのモバイルアプリケーションを `mobile` ユーザーの下で実行させています。各アプリケーションは Trusted BSD の強制アクセスコントロールフレームワークにより施行されたポリシーを使用して、サンドボックス化および制限されています。これらのポリシーはプロファイルと呼ばれ、すべてのサードパーティアプリケーションは汎用サンドボックスプロファイル、コンテナパーミッションリストで使用します。詳細については [Apple 開発者ドキュメントのアーカイブ](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AppSandboxInDepth/AppSandboxInDepth.html "Apple Developer Documentation on Sandboxing") と [新しい Apple 開発者セキュリティドキュメント](https://developer.apple.com/documentation/security "Apple Developer Security Documentation") を参照してください。

iOS では、アプリは以下のデータやリソースのいずれかにアクセスするためには、ユーザーにパーミッションを要求する必要があります。
- Bluetooth ペリフェラル
- カレンダーデータ
- カメラ
- 連絡先
- ヘルス共有
- ヘルス更新
- ホームキット
- ロケーション
- マイク
- モーション
- 音楽とメディアライブラリ
- 写真
- リマインダ
- Siri
- 音声認識
- テレビプロバイダ
詳細については、[アーカイブの iOS のアプリプログラミングガイド](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Data and resources protected by system authorization settings") と記事 [Apple 開発者ドキュメントでのユーザーのプライバシーの保護](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy "Protecting the User's Privacy") をご覧ください。
Apple はユーザーのプライバシーの保護を促し、[パーミッションを求める方法について非常にクリアである](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Requesting Permissions") とはいえ、アプリが非常に多くのパーミッションを要求するケースもまだあり得ます。

パーミッションが要求されているリソースの次には、デバイスを実行するためにアプリ開発者が必要とする一連の機能があります。これらの機能 (`UIRequiredDeviceCapabilities`) は [Apple 開発者ドキュメント](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW1 "UIRequiredDeviceCapabilities") にリストされています。これらの機能は App Store および iTunes により使用され、互換性のあるデバイスのみがリストされます。これらの機能の多くはユーザーがパーミッションを提供する必要がありません。実際に利用可能な機能はアプリケーションに署名するために使用される開発者プロファイルの種類ごとに異なることに注意します。詳細については [Apple 開発者ドキュメント](https://developer.apple.com/support/app-capabilities/ "Advanced App Capabilities") を参照してください。

#### 静的解析

iOS 10 以降では、パーミッションを検査する必要がある領域は三つあります。
- Info.plist ファイル
- `<appname>.enttitlements` ファイル (<appname> はアプリケーションの名前)
- ソースコード

##### Info.plist
Info.plist には保護されたデータやリソースにアクセスするためのパーミッションを要求する際にユーザーに提供するテキストが含まれています。[Apple ドキュメント](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Requesting Permission") では特定のリソースにアクセスするためのパーミッションをユーザーに求めるべき方法を明確に説明しています。これらのガイドラインに従うと、Info.plist ファイル内のそれぞれすべてのエントリを評価して、そのパーミッションが意味をなすかどうかを確認することが比較的簡単になります。
例えば、少なくとも以下のコンテンツを持つソリティアゲームの Info.plist がある場合。

```xml
<key>NSHealthClinicalHealthRecordsShareUsageDescription</key>
<string>Share your health data with us!</string>
<key>NSCameraUsageDescription</key>
<string>We want to access your camera</string>
```
通常のソリティアゲームはカメラやユーザーのヘルスレコードにアクセスする必要はないため疑う必要があります。
iOS 10 以降では、これらの \*Description フィールドで説明を提供する必要があることに注意します。探したいさまざまなキーのより完全な概要については [Apple アプリプログラミングガイド](https://developer.apple.com/library/archive/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/ExpectedAppBehaviors/ExpectedAppBehaviors.html#//apple_ref/doc/uid/TP40007072-CH3-SW7 "Apple app programming guide") の table 1-2 を参照してください。

##### Entitlements ファイル
entitlements ファイルはどの機能が使用されるかを示します。これらの機能の中にはユーザーにより提供される追加のパーミッションが必要なくても、依然として他のアプリに情報を漏洩する可能性があります。例えば App Groups 機能を利用します。[Apple 開発者ドキュメント](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html "Handling Common Scenarios") および [App Groups Entitlement](https://developer.apple.com/documentation/foundation/com_apple_security_application-groups?changes=_5&language=objc "Appl Groups Entitlement") に記載されています。この機能により、IPC または共有ファイルコンテナを介して異なるアプリ間で情報を共有することができます。つまりデータをアプリ間で直接デバイス上で共有できることを意味します。app-group 機能を持つアプリケーションエンタイトルメントファイルの例を以下に示します。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
  <!-- Note: this array contains all the capabilities registered for the app. -->
  <array/>
</dict>
</plist>
```

この要件はあるアプリケーションから他に情報を「流出」させるために必ずしも必要ではないことに注意します。情報を共有するために、二つのアプリケーション間の仲介としてバックエンドを使用することもできます。

##### ソースコード検査
<appname>.entitlements ファイルと Info.plist ファイルをチェックした後、要求されたパーミッションと割り当てられた機能がどのように使用されるかを検証する必要があります。これには、ソースコードレビューで十分です。
以下に注意を払います。
- Info.plist ファイルのパーミッションの説明がプログラムの実装と一致するかどうか。
- 機密情報が漏洩しないように、登録された機能が使用されているかどうか。

Info.plist ファイルに permission-explanation-text を登録せずにパーミッションを必要とする機能を使用することを要求された場合、アプリはクラッシュする可能性があることに注意します。

#### 動的解析
解析プロセスにはさまざまなステップがあります。
- embedded.mobileprovision ファイルと <appname>.entitlements をチェックし、含まれている機能を確認します。
- Info.plist ファイルを取得し、説明を提供するパーミッションをチェックします。
- アプリケーションを実行し、アプリケーションが他のアプリケーションやバックエンドと通信するかどうかをチェックします。パーミッションと機能を使用して取得した情報が悪意のある目的に使用されていないか、あるいは過度の活用や未活用ではないかをチェックします。


### カスタム URL スキームのテスト

#### 概要

Android の豊富なプロセス間通信 (IPC) 機能とは対照的に、iOS にはアプリ間の通信の選択肢がほとんどありません。実施、アプリが直接的に通信する方法はありません。代わりに、Apple は [二つのタイプの間接通信](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html "Inter-App Communication") を提供しています。AirDrop によるファイル転送とカスタム URL スキームです。

カスタム URL スキームを使用するとアプリはカスタムプロトコルを介して通信できます。アプリはスキームのサポートを宣言して、スキームを使用する着信 URL を処理する必要があります。URL スキームが登録されると、他のアプリはスキームを登録したアプリを開き、適切にフォーマットされた URL を作成して `openURL` メソッドで開くことでパラメータを渡すことができます。

セキュリティの問題は、アプリが URL とそのパラメータを適切に検証せずに URL スキームへのコールを処理する場合、およびユーザーが重要な操作を実行する前に確認を求められない場合に発生します。

一例として次の [Skype モバイルアプリのバグ](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html) があります。2010年に発見されました。Skype アプリは `skype://` プロトコルハンドラを登録しました。これにより他のアプリは他の Skype ユーザーや電話番号への呼び出しを実行できます。残念ながら、Skype は電話をかける前にユーザーに許可を求めないため、任意のアプリがユーザーの自覚なしに任意の番号を呼び出すことができます。

攻撃者はこの脆弱性を悪用して目に見えない `<iframe src="skype://xxx?call"></iframe>` (`xxx` は有料番号に置き換えられます) を置くことで、不注意に悪意のあるウェブサイトを訪れた任意の Skype ユーザーは有料番号を呼び出します。

#### 静的解析

カスタム URL スキームをテストするための最初のステップはアプリケーションがプロトコルハンドラを登録するかどうかを調べることです。この情報はアプリケーションサンドボックスフォルダのファイル `Info.plist` にあります。登録済みのプロトコルハンドラを表示するには、Xcode でプロジェクトを開き、`Info` タブに行き、下記のスクリーンショットにある `URL Types` セクションを開きます。

![Document Overview](Images/Chapters/0x06h/URL_scheme.png)

次に、URL パスの構築および検証方法を決定します。メソッド [`openURL`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc) はユーザー URL の処理を行います。実装されているコントロールを探します。URL はどのように検証されていますか (その入力は受け入れられますか) 、また、カスタム URL スキームを使用する際にユーザーの許可を必要としていますか。

コンパイル済みアプリケーションでは、登録済みのプロトコルハンドラはファイル `Info.plist` にあります。URL 構造体を見つけるには、`strings` または `Hopper` を使用して `CFBundleURLSchemes` キーの使用を探します。

```sh
$ strings <yourapp> | grep "myURLscheme://"
```

URL をコールする前に慎重に検証する必要があります。登録済みプロトコルハンドラを介して開くことができるアプリケーションをホワイトリストにできます。URL により発動されるアクションを確認するようユーザーに促すことはもう一つの有益なコントロールです。

#### 動的解析

アプリが登録したカスタム URL スキームを特定したら、Safari で URL を開き、そのアプリがどのように動作するか観察します。

アプリが URL のパーツを構文解析する場合、入力ファジングを実行してメモリ破損のバグを検出できます。これには [IDB](https://www.idbtool.com/) を使用できます。

- IDB を起動し、デバイスに接続してターゲットアプリを選択します。詳細は [IDB documentation](https://www.idbtool.com/documentation/setup.html) を参照します。
- `URL Handlers` セクションに移動します。`URL schemes` で `Refresh` をクリックすると、左側にはテスト対象アプリで定義されているすべてのカスタムスキームのリストがあります。これらのスキームをロードするには、右側にある `Open` をクリックします。ブランクの URI スキームを開く (例えば、`myURLscheme://` を開く) だけで、隠された機能 (例えば、デバッグウィンドウ) を発見してローカル認証をバイパスできます。
- カスタム URI スキームがバグを含むかどうかを調べるには、それらを fuzz してみます。`URL Handlers` セクションで、`Fuzzer` タブに移動します。左側にデフォルト IDB ペイロードがリストされます。[FuzzDB](https://github.com/fuzzdb-project/fuzzdb) プロジェクトにはファジング辞書が用意されています。ペイロードリストが準備できたら、左下の `Fuzz Template` セクションに移動してテンプレートを定義します。`$@$` を使用してインジェクションポイントを定義します。以下に例を示します。

```sh
myURLscheme://$@$
```

URL スキームをファジングする間、ログを見て (Xcode では、`Window -> Devices` に移動する `->` *デバイス上でクリックする* `->` *下部のコンソールにログがある*) 各ペイロードの影響を観察します。使用されたペイロードの履歴は IDB `Fuzzer` タブの右側にあります。

Needle を使用してカスタム URL スキームをテストできます。URL スキームに対して手動ファジングを実行して入力妥当性検査とメモリ破損バグを特定できます。以下の Needle モジュールを使用してこれらの攻撃を実行する必要があります。

```
[needle] >
[needle] > use dynamic/ipc/open_uri
[needle][open_uri] > show options

  Name  Current Value  Required  Description
  ----  -------------  --------  -----------
  URI                  yes       URI to launch, eg tel://123456789 or http://www.google.com/

[needle][open_uri] > set URI "myapp://testpayload'"
URI => "myapp://testpayload'"
[needle][open_uri] > run

```

### WebView プロトコルハンドラのテスト

#### 概要

WebView で解釈されるいくつかのデフォルトスキーマが利用可能です。以下のスキーマは iOS 上の WebView 内で使用できます。

-	http(s)://
-	file://
-	tel://

WebView はエンドポイントからリモートコンテンツをロードできますが、アプリデータディレクトリからローカルコンテンツをロードすることもできます。ローカルコンテンツがロードされる場合、ユーザーはファイル名やファイルをロードするために使用されるパスに影響を与えられるべきではなく、ユーザーはロードされたファイルを編集できるべきではありません。

#### 静的解析

WebView の使用状況についてソースコードを確認します。以下の WebView 設定はリソースへのアクセスを制御します。

- `allowFileAccessFromFileURLs`
- `allowUniversalAccessFromFileURLs`
- `allowingReadAccessToURL`

WebView で `allowFileAccessFromFileURLs` を設定する例:

Objective-C:
```objc

[webView.configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];

```

Swift:
```swift

webView.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")

```

デフォルトでは WKWebView はファイルアクセスが無効です。上記のメソッドの一つ以上が有効化されている場合、アプリが正しく機能するためにそのメソッドが本当に必要かどうかを判断する必要があります。

どの WebView クラスが使用されているかも確認してください。現在 WKWebView を使うべきであり、`UIWebView` は非推奨です。

WebView インスタンスが特定できた場合、ローカルファイルが [`loadFileURL`](https://developer.apple.com/documentation/webkit/wkwebview/1414973-loadfileurl?language=objc "loadFileURL") メソッドでロードされているかどうかを調べます。

Objective-C:
```objc

[self.wk_webview loadFileURL:url allowingReadAccessToURL:readAccessToURL];

```

Swift:
```swift

webview.loadFileURL(url, allowingReadAccessTo: bundle.resourceURL!)

```

`loadFileURL` で指定された URL は操作可能な動的パラメータについてチェックする必要があります。その操作はローカルファイルインクルージョンにつながる可能性があります。

HTML ページで [tel:// スキーマの検出を無効にする](https://developer.apple.com/library/content/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html "Phone Links on iOS") を選択すると、WebView で解釈されません。

多層防御策として以下のベストプラクティスを使用します。
- ロードを許可するローカルおよびリモートのウェブページとスキーマを定義するホワイトリストを作成します。
- ローカル HTML/JavaScript ファイルのチェックサムを作成し、アプリケーション起動時に確認します。JavaScript ファイルを圧縮して、それらを読みにくくします。

#### 動的解析

プロトコルハンドラの使用を特定するには、アプリを使用する中でファイルシステムからファイルにアクセスする方法や電話をかける方法を探します。

WebView 経由でローカルファイルをロードすることが可能な場合、このアプリはディレクトリトラバーサル攻撃に脆弱な可能性があります。これによりサンドボックス内のすべてのファイルにアクセス可能になり、(デバイスが脱獄されている場合) サンドボックスを脱出してファイルシステムにフルアクセスすることさえも可能になります。

したがって、ファイルがロードされるファイル名やパスをユーザーが変更できるかどうか、ロードされたファイルを編集できないかどうかを確認する必要があります。



### ネイティブメソッドが WebView を通じて公開されているかどうかを判断する

#### 概要

iOS バージョン 7.0 から、Apple は WebView の JavaScript ランタイムとネイティブの Swift や Objective-C オブジェクト間の通信を可能にする API を導入しました。これらの API を不用意に使用すると、重要な機能が攻撃者に晒され、(例えば、クロスサイトスクリプティング攻撃が成功することにより) WebView に悪意のあるスクリプトをインジェクトされる可能性があります。

#### 静的解析

`UIWebView` と `WKWebView` は両方とも WebView とネイティブアプリの間の通信手段を提供します。WebView JavaScript エンジンに公開されている重要なデータやネイティブ機能は WebView で実行している不正な JavaScript にもアクセスできます。

iOS 7 以降、JavaScriptCore フレームワークは WebKit JavaScript エンジンに Objective-C ラッパーを提供しています。これにより Swift や Objective-C から JavaScript を実行できるほか、JavaScript ランタイムから Objective-C や Swift オブジェクトにアクセスできます。JavaScript 実行環境は `JSContext` オブジェクトで表されます。WebView に関連付けられた `JSContext` にネイティブオブジェクトをマップするコードを探し、どのような機能が公開されているかを解析します。例えば、機密データは WebView にアクセス可能で公開されていてはいけません。Objective-C では、`UIWebView` に関連付けられた `JSContext` は以下のように取得されます。

```objc

[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]

```

ネイティブコードと JavaScript が通信するには二つの基本的な方法があります。

- **JSContext**: Objective-C ブロックや Swift ブロックが JSContext の識別子に割り当てられると、JavaScriptCore はそのブロックを JavaScript 関数で自動的にラップします。
- **JSExport protocol**: JSExport 継承されたプロトコルで宣言されたプロパティ、インスタンスメソッド、クラスメソッドは JavaScript オブジェクトにマップされ、すべての JavaScript コードで利用できます。JavaScript 環境にあるオブジェクトの変更はネイティブ環境に反映されます。

`JSExport` プロトコルで定義されたクラスメンバだけが JavaScript コードにアクセス可能となることに注意します。

#### 動的解析

アプリの動的解析ではアプリの使用中にロードされる HTML ファイルや JavaScript ファイルを示します。潜在的な攻撃領域の概要を知るためには、iOS アプリのすべての WebView を見つける必要があります。

JSContext および JSExport の使用は静的解析を通じて特定されることが理想であり、また、WebView にどの機能が公開および表示されているかを識別すべきです。関数を悪用する手順は、JavaScript ペイロードを生成して、それをアプリが要求するファイルにイジェクトすることから始まります。インジェクションは中間者攻撃を介して達成できます。[#THIEL] 156 ページにある WebView に公開された脆弱な iOS アプリと機能の例を参照してください。


### iOS WebView のテスト

#### 概要

WebView はインタラクティブなウェブコンテンツを表示するためのアプリ内ブラウザコンポーネントです。それらを使用してウェブコンテンツをアプリのユーザーインタフェースに直接埋め込むことができます。iOS WebView はデフォルトで JavaScript の実行をサポートしているため、スクリプトインジェクションやクロスサイトスクリプティング攻撃がそれらに影響を及ぼす可能性があります。

#### 静的解析

WebView を実装する以下のクラスの使い方に注意します。

- [UIWebView](https://developer.apple.com/reference/uikit/uiwebview "UIWebView reference documentation") (iOS バージョン 7.1.2 およびそれ以前)
- [WKWebView](https://developer.apple.com/reference/webkit/wkwebview "WKWebView reference documentation") (iOS バージョン 8.0 およびそれ以降)
- [SFSafariViewController](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)

`UIWebView` は非推奨であり使用すべきではありません。`WKWebView` または `SafariViewController` のいずれかが埋め込みウェブコンテンツに使用されていることを確認します。

- `WKWebView` はアプリの機能を拡張したり、表示されるコンテンツを制御 (すなわち、ユーザーが任意の URL にナビゲートすることを予防) したり、カスタマイズしたりするための適切な選択です。
- `SafariViewController` は一般的なウェブ閲覧エクスペリエンスを提供するために使用すべきです。

> `SafariViewController` は cookie と他のウェブサイトのデータを Safari と共有することに注意します。

`WKWebView` には `UIWebView` よりもいくつかのセキュリティ上の利点があります。

- `JavaScriptEnabled` プロパティを使用して WKWebView 上の JavaScript を完全に無効にできます。これはすべてのスクリプトインジェクションの欠陥を防止します。
- `JavaScriptCanOpenWindowsAutomatically` を使用して JavaScript がポップアップなどの新しいウィンドウを開くことを防止できます。
- `hasOnlySecureContent` プロパティを使用して WebView によりロードされたリソースが暗号化された接続を通じて取得されたことを検証できます。
- WKWebView はアウトオブプロセスレンダリングを実装しているため、メモリ破損のバグがメインのアプリプロセスに影響を与えません。

また、WKWebView は Nitro JavaScript エンジンを使用して、WebView を使用しているアプリのパフォーマンスを大幅に向上します [#THIEL] 。

##### JavaScript 設定

ベストプラクティスとして、明示的に必要とされない限り `WKWebView` の JavaScript を無効にします。以下のコードサンプルではサンプル設定を示しています。

```objc

#import "ViewController.h"
#import <WebKit/WebKit.h>
@interface ViewController ()<WKNavigationDelegate,WKUIDelegate>
@property(strong,nonatomic) WKWebView *webView;
@end

@implementation ViewController

- (void)viewDidLoad {

    NSURL *url = [NSURL URLWithString:@"http://www.example.com/"];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    WKPreferences *pref = [[WKPreferences alloc] init];

    //Disable javascript execution:
    [pref setJavaScriptEnabled:NO];
    [pref setJavaScriptCanOpenWindowsAutomatically:NO];

    WKWebViewConfiguration *conf = [[WKWebViewConfiguration alloc] init];
    [conf setPreferences:pref];
    _webView = [[WKWebView alloc]initWithFrame:CGRectMake(self.view.frame.origin.x,85, self.view.frame.size.width, self.view.frame.size.height-85) configuration:conf] ;
    [_webView loadRequest:request];
    [self.view addSubview:_webView];

}

```

`SafariViewController` では JavaScript は無効にできません。目標がアプリのユーザーインタフェースを拡張することである場合、これが `WKWebView` の使用を推奨する理由の一つです。

###### WKWebView

`UIWebView` とは対照的に、`WKWebView` の `JSContext` を直接参照することはできません。代わりに、メッセージングシステムを使用して通信が実装されています。JavaScript コードは 'postMessage' メソッドを使用してネイティブアプリにメッセージを送り返すことができます。

```javascript

window.webkit.messageHandlers.myHandler.postMessage()

````

`postMessage` API は JavaScript オブジェクトをネイティブ Objective-C または Swift オブジェクトに自動的にシリアライズします。メッセージハンドラは `addScriptMessageHandler` メソッドを使用して設定されます。


##### ローカルファイルインクルージョン

WebView はコンテンツをリモートで、およびアプリデータディレクトリからローカルでロードできます。コンテンツをローカルでロードする場合、ユーザーはロードされるファイルのファイル名やパスを変更できるべきではなく、ロードされたファイルを編集できるべきではありません。

WebView を使用するソースコードを確認します。WebView インスタンスを特定できる場合、ローカルファイルがロードされているかどうかをチェックします (以下の例では "example_file.html") 。

```objc

- (void)viewDidLoad
{
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];

    self.webView = [[WKWebView alloc] initWithFrame:CGRectMake(10, 20, CGRectGetWidth([UIScreen mainScreen].bounds) - 20, CGRectGetHeight([UIScreen mainScreen].bounds) - 84) configuration:configuration];
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"example_file" ofType:@"html"];
    NSString *html = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    [self.webView loadHTMLString:html baseURL:[NSBundle mainBundle].resourceURL];
}

```

`baseURL` で (ローカルファイルインクルージョンにつながる) 操作可能な動的パラメータを確認します。

##### `hasOnlySecureContent`

WKWebView では複合コンテンツや完全に HTTP 経由でロードされたコンテンツを検出することができます。`hasOnlySecureContent` メソッドを使用することにより HTTPS 経由のコンテンツだけを表示することが保証され、そうでない場合にはユーザーに警告が表示されます。例については [#THIEL] の 159 および 160 ページを参照してください。

#### 動的解析

攻撃をシミュレートするには、傍受プロキシを使用して WebView に独自の JavaScript をインジェクトします。JavaScript コンテキストに露出している可能性のあるローカルストレージやネイティブメソッドやプロパティにアクセスを試みます。

現実のシナリオでは、永続的なバックエンドのクロスサイトスクリプティング脆弱性や中間者攻撃を介してのみ JavaScript をインジェクトできます。詳細については OWASP [XSS cheat sheet](https://goo.gl/x1mMMj "XSS (Cross Site Scripting) Prevention Cheat Sheet") [(日本語訳)](https://jpcertcc.github.io/OWASPdocuments/CheatSheets/XSSPrevention.html) や「ネットワーク通信のテスト」を参照してください。

### オブジェクトの永続性のテスト

#### 概要

iOS でオブジェクトを永続化する方法はいくつかあります。

##### オブジェクトエンコーディング
iOS には Objective-C や NSObject のオブジェクトエンコーディングおよびデコーディングのための二つのプロトコル `NSCoding` と `NSSecureCoding` があります。クラスがいずれかのプロトコルに準拠する場合、そのデータは `NSData` バイトバッファ用のラッパーにシリアライズされます。Swift の `Data` は `NSData` やそのミュータブル対応の `NSMutableData` と同じであることに注意します。`NSCoding` プロトコルはそのインスタンス変数をエンコードやデコードするために実装される必要がある二つのメソッドを宣言します。NSCoding を使用するクラスは NSObject を実装するか @objc クラスとしてアノテーションを付ける必要があります。NSCoding プロトコルは以下に示すように encode と init を実装する必要があります。

```swift
class CustomPoint: NSObject, NSCoding {

	//required by NSCoding:
	func encode(with aCoder: NSCoder) {
		aCoder.encode(x, forKey: "x")
		aCoder.encode(name, forKey: "name")
	}

	var x: Double = 0.0
	var name: String = ""

	init(x: Double, name: String) {
			self.x = x
			self.name = name
	}

	// required by NSCoding: initalize members using a decoder.
	required convenience init?(coder aDecoder: NSCoder) {
			guard let name = aDecoder.decodeObject(forKey: "name") as? String
					else {return nil}
			self.init(x:aDecoder.decodeDouble(forKey:"x"),
								name:name)
	}

	//getters/setters/etc.
}
```

`NSCoding` の問題は、クラス型を評価する前にたいていはオブジェクトがすでに構築および挿入されることです。これにより攻撃者はあらゆる種類のデータを簡単に注入できます。そのため、`NSSecureCoding` プロトコルが導入されました。`NSSecureCoding` に準拠する場合には、`init(coder:)` がクラスの一部であるとき、以下を含める必要があります。

```swift

static var supportsSecureCoding: Bool {
        return true
}
```

次に、オブジェクトをデコードするときに、例えば以下のようなチェックが行われるべきです。
```Swift
let obj = decoder.decodeObject(of:MyClass.self, forKey: "myKey")
```
*ソース: https://developer.apple.com/documentation/foundation/NSSecureCoding*

`NSSecureCoding` への準拠はインスタンス化されたオブジェクトが確かに期待されたものであることを保証します。但し、そのデータに対するさらなる整合性チェックは行われず、そのデータは暗号化されません。したがって、任意の秘密のデータには追加の暗号化を必要とし、データの整合性を保護する必要があるため、追加の HMAC を取得すべきです。

注、`NSData` (Objective-C) やキーワード `let` (Swift) が使用されている場合、そのデータはメモリ内でイミュータブルであり、簡単には削除できません。


##### NSKeyedArchiver を使用したオブジェクトのアーカイブ
`NSKeyedArchiver` は NSCoder の具象サブクラスであり、オブジェクトをエンコードしてファイルに格納する方法を提供します。`NSKeyedUnarchiver` はそのデータをデコードして、元のデータを再作成します。`NSCoding` セクションの例を取り、それらをアーカイブおよび展開してみましょう。

```swift

//archiving:
NSKeyedArchiver.archiveRootObject(customPoint, toFile: "/path/to/archive")

//unarchiving:
guard let customPoint = NSKeyedUnarchiver.unarchiveObjectWithFile("/path/to/archive") as? CustomPoint else { return nil }

```

キー付きアーカイブをデコードする場合、値は名前により要求されるため、値は順不同でデコードされるか全くデコードされません。したがって、キー付きアーカイブは前方互換性と後方互換性のより良いサポートを提供します。つまり、ディスク上のアーカイブには、その与えられたデータのキーが後のステージで提供されない限り、プログラムにより検出されない追加データが実際に含まれる可能性があります。

機密データの場合にファイルをセキュアにするには、そのデータがファイル内で暗号化されないため、追加の保護が必要であることに注意します。詳細についてはデータストレージセクションを参照してください。

##### Codable
Swift 4 では `Codable` 型のエイリアスが到来しました。これは `Decodable` と `Encodable` プロトコルの組み合わせです。String, Int, Double, Date, Data, URL は本質的に Codable です。つまり、追加作業なしで簡単にエンコードおよびデコードできます。以下の例を見てみましょう。

```swift
struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}
```

この例の `CustomPointStruct` の継承リストに `Codable` を追加することにより、`init(from:)` および `encode(to:)` メソッドが自動的にサポートされます。`Codable` の動作についての詳細は [Apple 開発者ドキュメント](https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types "Codable") を参照してください。
`Codable` は `NSCoding`/`NSSecureCoding`, JSON, プロパティリスト, XML などを使用して NSData をさまざまな表現に簡単にエンコードやデコードできます。詳細についてはこの章の他のサブセクションを参照してください。

##### JSON と Codable
さまざまなサードパーティライブラリを使用して iOS 内で JSON をエンコードおよびデコードするいろいろな方法があります。
- [Mantle](https://github.com/Mantle/Mantle "Mantle"),
- [JSONModel library](https://github.com/jsonmodel/jsonmodel "JSONModel"),
- [SwiftyJSON library](https://github.com/SwiftyJSON/SwiftyJSON "SwiftyJSON"),
- [ObjectMapper library](https://github.com/Hearst-DD/ObjectMapper, "ObjectMapper library"),
- [JSONKit](https://github.com/johnezang/JSONKit "JSONKit"),
- [JSONModel](https://github.com/JSONModel/JSONModel "JSONModel"),
- [YYModel](https://github.com/ibireme/YYModel "YYModel"),
- [SBJson 5](https://github.com/ibireme/YYModel "SBJson 5"),
- [Unbox](https://github.com/JohnSundell/Unbox "Unbox"),
- [Gloss](https://github.com/hkellaway/Gloss "Gloss"),
- [Mapper](https://github.com/lyft/mapper "Mapper"),
- [JASON](https://github.com/delba/JASON "JASON"),
- [Arrow](https://github.com/freshOS/Arrow "Arrow").

これらのライブラリは、Swift および Objective-C の特定バージョンのサポート、返す結果が mutable であるか immutable であるか、速度、メモリ消費量、実際のライブラリサイズが異なります。
改めて、immutable の場合の注意です。機密情報を簡単にメモリから削除することはできません。

次に、Apple は `Codable` と `JSONEncoder` および `JSONDecoder` を組み合わせて JSON エンコーディングおよびデコーディングの直接的なサポートを提供しています。

```swift
struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}

let encoder = JSONEncoder()
encoder.outputFormatting = .prettyPrinted

let test = CustomPointStruct(x: 10, name: "test")
let data = try encoder.encode(test)
print(String(data: data, encoding: .utf8)!)
// Prints:
// {
//   "x" : 10,
//   "name" : "test"
// }

```

JSON 自体は (NoSQL) データベースやファイルなどどこにでも格納できます。あなたは機密を含む JSON が適切に保護 (暗号化や HMAC など) されていることを確認する必要があります。詳細についてはデータストレージの章を参照してください。


##### プロパティリストと Codable

オブジェクトを `PropertyList` (以前のセクションでは Plist とも呼ばれています) に永続化できます。以下に使用方法の例が二つあります。

```swift

//archiving:
let data = NSKeyedArchiver.archivedDataWithRootObject(customPoint)
NSUserDefaults.standardUserDefaults().setObject(data, forKey: "customPoint")

//unarchiving:

if let data = NSUserDefaults.standardUserDefaults().objectForKey("customPoint") as? NSData {
    let customPoint = NSKeyedUnarchiver.unarchiveObjectWithData(data)
}

```
この一つ目の例では、`NSUserDefaults` が使用されています。これはプライマリの `PropertyList` です。`Codable` バージョンでも同じことができます。

```swift

struct CustomPointStruct:Codable {
    var x: Double
    var name: String
}

var points: [CustomPointStruct] = [
    CustomPointStruct(x: 1, name "test"),
    CustomPointStruct(x: 2, name "test"),
    CustomPointStruct(x: 3, name "test"),
]

UserDefaults.standard.set(try? PropertyListEncoder().encode(points), forKey:"points")
if let data = UserDefaults.standard.value(forKey:"points") as? Data {
    let points2 = try? PropertyListDecoder().decode(Array<CustomPointStruct>.self, from: data)
}

```
PropertyList ファイルは機密情報を格納するためのものではないことに注意します。これらはアプリのユーザー設定を保持するように設計されています。

##### XML
XML エンコーディングを行うには複数の方法があります。JSON パーサーと同様に、以下のようなさまざまなサードパーティライブラリがあります。
- [Fuzi](https://github.com/cezheng/Fuzi "Fuzi"),
- [Ono](https://github.com/mattt/Ono "Ono"),
- [AEXML](https://github.com/tadija/AEXML "AEXML"),
- [RaptureXML](https://github.com/ZaBlanc/RaptureXML "RaptureXML"),
- [SwiftyXMLParser](https://github.com/yahoojapan/SwiftyXMLParser "SwiftyXMLParser"),
- [SWXMLHash](https://github.com/drmohundro/SWXMLHash "SWXMLHash").

これらは速度、メモリ使用量、オブジェクトの永続性の点で異なります。またより重要な点として XML 外部エンティティの処理方法が異なります。例として [Apple iOS Office ビューアの XXE](https://nvd.nist.gov/vuln/detail/CVE-2015-3784 "CVE-2015-3784") を参照してください。したがって、可能であれば外部エンティティの解析を無効化することが重要です。詳細は [OWASP XXE prevention cheatsheet](https://goo.gl/86epVd "XXE prevention cheatsheet") を参照してください。
これらのライブラリのほかに、Apple の [XMLParser クラス](https://developer.apple.com/documentation/foundation/xmlparser "XMLParser") を使用することができます。

サードパーティライブラリを使用せずに、Apple の `XMLParser` を使用する場合には、`shouldResolveExternalEntities` が false を返すようにしてください。

##### ORM (Coredata と Realm)
iOS にはさまざまな ORM ライクなソリューションがあります。最初のものは [Realm](https://realm.io/docs/swift/latest/ "Realm") で、独自のストレージエンジンが付属しています。Realm には [Realm のドキュメント](https://academy.realm.io/posts/tim-oliver-realm-cocoa-tutorial-on-encryption-with-realm/ "Enable encryption") で説明されているように、データを暗号化する設定があります。これによりセキュアなデータを扱うことができます。この暗号化はデフォルトではオフであることに注意します。

Apple 自身も CoreData を提供しています。CoreData は [Apple 開発者ドキュメント](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/index.html#//apple_ref/doc/uid/TP40001075-CH2-SW1, "CoreData") で詳細に説明されています。[Apple の PersistentStoreFeatures ドキュメント](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/CoreData/PersistentStoreFeatures.html "PersistentStoreFeatures") で説明されているようにさまざまなストレージバックエンドをサポートしています。Apple が推奨するストレージバックエンドの問題は、いずれのタイプのデータストアも暗号化されないことと、完全性がチェックされないことです。したがって、機密データの場合には追加の措置が必要となります。代替はプロジェクト [iMas](https://github.com/project-imas/encrypted-core-data "Encrypted Core Data") にあります。これは独自の暗号化を提供します。

##### プロトコルバッファ
Google の [プロトコルバッファ](https://developers.google.com/protocol-buffers/ "Google Documentation") は[バイナリデータ形式](https://developers.google.com/protocol-buffers/docs/encoding "Encoding") を用いて構造化データをシリアル化するためのプラットフォームおよび言語に中立のメカニズムです。これらは [Protobuf](https://github.com/apple/swift-protobuf "Protobuf") ライブラリを用いて iOS で利用できます。
プロトコルバッファには [CVE-2015-5237](https://www.cvedetails.com/cve/CVE-2015-5237/ "CVE-2015-5237") などのいくつかの脆弱性があります。
プロトコルバッファは機密性の保護を提供しないことに注意します。暗号化は組み込まれていません。


#### 静的解析
さまざまな種類のオブジェクト永続性では以下の懸念事項を共有します。

- オブジェクト永続性を使用してデバイスに機密データを格納する場合、データベースレベルか厳密に値レベルのいずれかで、データが暗号化されていることを確認します。
- 情報の完全性を保証する必要がありますか？ HMAC メカニズムを使用するか格納する情報に署名します。オブジェクトに格納されている実際の情報を処理する前に必ず HMAC や署名を検証します。
- 上述の二つの考えで使用される鍵が安全に KeyChain に格納され、十分に保護されていることを確認します。詳細についてはデータストレージのセクションを参照してください。
- 逆シリアル化されたオブジェクト内のデータは実際に使用する前に慎重に検証されていることを確認します (ビジネスロジックやアプリケーションロジックの悪用がないことなど) 。
- 高リスクアプリケーションのオブジェクトをシリアル化や逆シリアル化するために [実行時参照](https://developer.apple.com/library/archive/#documentation/Cocoa/Reference/ObjCRuntimeRef/Reference/reference.html "Objective-C runtime reference") を使用する永続性メカニズムを使用してはいけません。攻撃者がこのメカニズムを介してビジネスロジックを実行する手順を操作できる可能性があるためです (詳細についてはアンチリバースエンジニアリングの章を参照してください) 。
- Swift 2 以降では、[Mirror](https://developer.apple.com/documentation/swift/mirror "Mirror") を使用してオブジェクトの一部を読み取ることができますが、そのオブジェクトに対しての書き込みには使用できないことに注意します。

#### 動的解析
動的解析を実行する方法はいくつかあります。

- 実際の永続性の場合：データストレージの章で説明した技法を使用します。
- シリアル化自体の場合：デバッグビルドを使用するか Frida/Objection を使用してシリアル化メソッドがどのように処理されるかを確認します (アプリケーションがクラッシュするか、オブジェクトを肥やすことで余計な情報を抽出できるかなど) 。



### 参考情報

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition.
- Security Flaw with UIWebView - (https://medium.com/ios-os-x-development/security-flaw-with-uiwebview-95bbd8508e3c "Security Flaw with UIWebView")

#### OWASP Mobile Top 10 2016

- M1 - Improper Platform Usage - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.1: "アプリは必要となる最低限のパーミッションのみを要求している。"
- V6.3: "アプリはメカニズムが適切に保護されていない限り、カスタムURLスキームを介して機密な機能をエクスポートしていない。"
- V6.5: "明示的に必要でない限りWebViewでJavaScriptが無効化されている。"
- V6.6: "WebViewは最低限必要のプロトコルハンドラのセットのみを許可するよう構成されている（理想的には、httpsのみがサポートされている）。file, tel, app-id などの潜在的に危険なハンドラは無効化されている。"
- V6.7: "アプリのネイティブメソッドがWebViewに公開されている場合、WebViewはアプリパッケージ内に含まれるJavaScriptのみをレンダリングしている。"
- V6.8: "オブジェクトのデシリアライゼーションは、もしあれば、安全なシリアライゼーションAPIを使用して実装されている。"


#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-200 - Information Leak / Disclosure
- CWE-939 - Improper Authorization in Handler for Custom URL Scheme


#### ツール

- IDB - https://www.idbtool.com/

#### iOS におけるオブジェクト永続性について
- https://developer.apple.com/documentation/foundation/NSSecureCoding
- https://developer.apple.com/documentation/foundation/archives_and_serialization?language=swift
- https://developer.apple.com/documentation/foundation/nskeyedarchiver
- https://developer.apple.com/documentation/foundation/nscoding?language=swift,https://developer.apple.com/documentation/foundation/NSSecureCoding?language=swift
- https://developer.apple.com/documentation/foundation/archives_and_serialization/encoding_and_decoding_custom_types
- https://developer.apple.com/documentation/foundation/archives_and_serialization/using_json_with_custom_types
- https://developer.apple.com/documentation/foundation/jsonencoder
- https://medium.com/if-let-swift-programming/migrating-to-codable-from-nscoding-ddc2585f28a4
- https://developer.apple.com/documentation/foundation/xmlparser
