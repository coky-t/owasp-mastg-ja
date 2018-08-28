## iOS のプラットフォーム API

### カスタム URL スキームのテスト

#### 概要

Android の豊富なプロセス間通信 (IPC) 機能とは対照的に、iOS にはアプリ間の通信の選択肢がほとんどありません。実施、アプリが直接的に通信する方法はありません。代わりに、Apple は [二つのタイプの間接通信](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html) を提供しています。AirDrop によるファイル転送とカスタム URL スキームです。

カスタム URL スキームを使用するとアプリはカスタムプロトコルを介して通信できます。アプリはスキームのサポートを宣言して、スキームを使用する着信 URL を処理する必要があります。URL スキームが登録されると、他のアプリはスキームを登録したアプリを開き、適切にフォーマットされた URL を作成して `openURL` メソッドで開くことでパラメータを渡すことができます。

セキュリティの問題は、アプリが URL とそのパラメータを適切に検証せずに URL スキームへのコールを処理する場合、およびユーザーが重要な操作を実行する前に確認を求められない場合に発生します。

一例として次の [Skype モバイルアプリのバグ](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html) があります。2010年に発見されました。Skype アプリは `skype://` プロトコルハンドラを登録しました。これにより他のアプリは他の Skype ユーザーや電話番号への呼び出しを実行できます。残念ながら、Skype は電話をかける前にユーザーに許可を求めないため、任意のアプリがユーザーの自覚なしに任意の番号を呼び出すことができます。

攻撃者はこの脆弱性を悪用して目に見えない `<iframe src="skype://xxx?call"></iframe>` (`xxx` は有料番号に置き換えられます) を置くことで、不注意に悪意のあるウェブサイトを訪れた任意の Skype ユーザーは有料番号を呼び出します。

#### 静的解析

カスタム URL スキームをテストするための最初のステップはアプリケーションがプロトコルハンドラを登録するかどうかを調べることです。この情報はアプリケーションサンドボックスフォルダのファイル `info.plist` にあります。登録済みのプロトコルハンドラを表示するには、Xcode でプロジェクトを開き、`Info` タブに行き、下記のスクリーンショットにある `URL Types` セクションを開きます。

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
```
[self.wk_webview loadFileURL:url allowingReadAccessToURL:readAccessToURL];
```

Swift:
```
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

### iOS WebView のテスト

#### 概要

WebView はアプリ内ブラウザコンポーネントです。インタラクティブなウェブコンテンツを表示します。それらを使用してアプリのユーザーインタフェース内に直接ウェブコンテンツを埋め込むことができます。

iOS WebView はデフォルトで JavaScript の実行をサポートしているため、スクリプトインジェクションやクロスサイトスクリプティング攻撃の影響を受ける可能性があります。iOS バージョン 7.0 から、Apple も WebView の JavaScript ランタイムとネイティブ Swift や Objective-C アプリとの間で通信を可能にする API を導入しました。これらの API を不用意に使用すると、重要な機能が攻撃者に晒され、WebView に悪意のあるスクリプトをインジェクトされ (例えば、クロスサイトスクリプティング攻撃が成功することにより) 管理される可能性があります。

潜在的なスクリプトインジェクションのほかに、WebView の別の基本的なセキュリティ問題があります。iOS にパッケージ化された WebKit ライブラリは Safari ウェブブラウザのようにアウトオブバンドで更新されることはありません。したがって、新たに発見された WebKit の脆弱性は次の iOS アップデートまで悪用可能なまま残ります [#THIEL] 。

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

##### ネイティブオブジェクトの露出

`UIWebView` と `WKWebView` は両方とも WebView とネイティブアプリの間の通信手段を提供します。WebView JavaScript エンジンに公開されている重要なデータやネイティブ機能は WebView で実行している不正な JavaScript にもアクセスできます。

###### UIWebView

iOS 7 以降、JavaScriptCore フレームワークは WebKit JavaScript エンジンに Objective-C ラッパーを提供しています。これにより Swift や Objective-C から JavaScript を実行できるほか、JavaScript ランタイムから Objective-C や Swift オブジェクトにアクセスできます。

JavaScript 実行環境は `JSContext` オブジェクトで表されます。WebView に関連付けられた `JSContext` にネイティブオブジェクトをマップするコードに注意します。Objective-C では、`UIWebView` に関連付けられた `JSContext` は以下のように取得されます。

``objc
[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]
``

- Objective-C ブロック。Objective-C ブロックが JSContext の識別子に割り当てられると、JavaScriptCore はそのブロックを JavaScript 関数で自動的にラップします。
- JSExport プロトコル。JSExport 継承されたプロトコルで宣言されたプロパティ、インスタンスメソッド、クラスメソッドは JavaScript オブジェクトにマップされ、すべての JavaScript コードで利用できます。JavaScript 環境にあるオブジェクトの変更はネイティブ環境に反映されます。

`JSExport` プロトコルで定義されたクラスメンバだけが JavaScript コードにアクセス可能となることに注意します。

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

現実のシナリオでは、永続的なバックエンドのクロスサイトスクリプティング脆弱性や中間者攻撃を介してのみ JavaScript をインジェクトできます。詳細については OWASP [XSS cheat sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting\)\_Prevention_Cheat_Sheet "XSS (Cross Site Scripting) Prevention Cheat Sheet") [(日本語訳)](https://jpcertcc.github.io/OWASPdocuments/CheatSheets/XSSPrevention.html) や「ネットワーク通信のテスト」を参照してください。

### 参考情報

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition.
- Security Flaw with UIWebView - (https://medium.com/ios-os-x-development/security-flaw-with-uiwebview-95bbd8508e3c "Security Flaw with UIWebView")

#### OWASP Mobile Top 10 2016

- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M7-Poor_Code_Quality.html

#### OWASP MASVS

- V6.3: "アプリはメカニズムが適切に保護されていない限り、カスタムURLスキームを介して機密な機能をエクスポートしていない。"
- V6.5: "明示的に必要でない限りWebViewでJavaScriptが無効にされている。"
- V6.6: "WebViewは最低限必要なプロトコルハンドラのセットのみを許可するよう構成されている（理想的には、httpsのみがサポートされている）。file, tel, app-id などの潜在的に危険なハンドラは無効にされている。"
- V6.7: "アプリのネイティブメソッドがWebViewに公開されている場合、WebViewはアプリパッケージ内に含まれるJavaScriptのみをレンダリングしている。"

#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-939: Improper Authorization in Handler for Custom URL Scheme

#### ツール

- IDB - https://www.idbtool.com/
